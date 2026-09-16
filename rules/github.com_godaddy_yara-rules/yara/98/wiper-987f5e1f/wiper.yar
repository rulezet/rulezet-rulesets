rule wiper {
    meta:
        description = "Wiper malware deployed in late 2014 skywiper attacks"

    strings:
                $decryption_main_loop = {8bcbe8????????8a143e32d088143e463bf57cec5f}
                $context_init_loop1 = { 8b790c8b411033f78971088bf033f789710c8b710833c64b89411075e3 }
                $context_init_loop2 = { 8b510c8b41100bf28971088bf00bf289710c8b71080bc64f89411075e3 }
        $MZ = "MZ"

    condition:
        $MZ at 0 and 2 of them
}