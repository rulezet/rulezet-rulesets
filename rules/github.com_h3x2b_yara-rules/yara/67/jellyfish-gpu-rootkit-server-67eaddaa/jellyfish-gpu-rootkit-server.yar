rule jellyfish_gpu_rootkit_server: malware linux rootkit
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects Jellyfish samples - 201505"
                                        
    strings:
        $m_01 = "gpu.txt"

        $o_01 = "socket failed!"
        $o_02 = "couldn't bind socket!"
        $o_03 = "couldn't setup listener socket!"
        $o_04 = "accept() socket failed!"
        $o_05 = "recv() failed! trying again...\n"
        $o_06 = "%s  |  Logged to gpu.txt\n"

    condition:
                uint32be(0) == 0x7f454c46 and

                all of ($m_*) and

                4 of ($o_*)

}