rule irctelnet__payload: malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects malicious payload of the irctelnet - 20161102"
                                        
    strings:
        $irc_00 = "PASS %s"
        $irc_01 = "NICK %s"
        $irc_02 = "USER %s . . : ."
        $irc_03 = "USER d3x . . : ."
        $irc_04 = "ERROR"
        $irc_05 = "-sh"
        $irc_06 = "GET / HTTP/1.0"
        $irc_07 = "Host: %s"

        $x_00 = "ogin:"
        $x_01 = "assword:"
        $x_02 = "ncorrect"
        $x_03 = "failed"
        $x_04 = "built-in commands"
        $x_05 = "seconds"
        $x_06 = "shell"
        $x_07 = "(y/N)"
        $x_08 = "free"
        $x_09 = "mkdir -p %s && rm -f %s/*; ftpget -u ftp %s %s/%s %s 2>&1 || wget -O %s/%s http://%s/%s 2>&1 || tftp -g -r "
        $x_10 = "/etc/firewall_stop"
        

    condition:
                uint32be(0) == 0x7f454c46 and

                all of ($irc_*) and

                all of ($x_*)
}