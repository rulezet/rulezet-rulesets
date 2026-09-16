rule CrowdStrike_PutterPanda_02 : rc4_dropper putterpanda
	{
	meta:
		description = "PUTTER PANDA - RC4 dropper"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $res_lock = "LockResource"
	    $res_size = "SizeofResource"
	    $res_load = "LoadResource"
	
	    $com = "COMSPEC"
	
	    	    	    	    	    	    	
	    $cryptaq = "CryptAcquireContextA"
	
	condition:
	    uint16(0) == 0x5A4D and
	    (all of ($res_*)) and 
	    
	    $cryptaq and $com
	}