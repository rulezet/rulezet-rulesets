rule warning_vb_potential_heapspray {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 2
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
	release = "lite"
        sigtype = "cryptam_exploit"
        desc = "office heap spray"
    strings:
        $s1 = "90909090EB7F414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141412490909090"
    condition:
        1 of them
    }