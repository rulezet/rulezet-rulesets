rule Linux_Rootkit_Reptile_eb201301 {
    meta:
        author = "Elastic Security"
        id = "eb201301-b10b-4c88-ae45-6cceb2f6ef6e"
        fingerprint = "7f1948a9e08c3ad9db3492112590bf5f10eb7b992fe3ab5cc5fc52bf81897378"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "Reptile Packet Sender"
        $str2 = "Written by F0rb1dd3n"
        $str3 = "Reptile Wins"
        $str4 = "Written by: F0rb1dd3n"
        $opt1 = "-r Remote port from magic packets (only for tcp/udp)"
        $opt2 = "-x Magic Packet protocol (tcp/icmp/udp)"
        $opt3 = "-s Source IP address to spoof"
        $opt4 = "-q Source port from magic packets (only for tcp/udp)"
        $opt5 = "-l Host to receive the reverse shell"
        $opt6 = "-p Host port to receive the reverse shell"
        $opt7 = "-k Token to trigger the port-knocking"
        $help1 = "Run the listener and send the magic packet"
        $help2 = "Local host to receive the shell"
        $help3 = "Local port to receive the shell"
        $help4 = "Source host on magic packets (spoof)"
        $help5 = "Source port on magic packets (only for TCP/UDP)"
        $help6 = "Remote port (only for TCP/UDP)"
        $help7 = "Protocol to send magic packet (ICMP/TCP/UDP)"
        $rep1 = "Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]"
        $rep2 = "S3cr3tP@ss"
    condition:
        all of ($rep*) or (1 of ($str*) and (4 of ($opt*) or 4 of ($help*)))
}