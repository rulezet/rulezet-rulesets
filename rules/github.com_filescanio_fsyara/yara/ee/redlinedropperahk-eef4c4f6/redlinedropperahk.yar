rule RedLineDropperAHK : hardened
{
	meta:
		author = "ditekshen"
		description = "RedLine infostealer payload"
		cape_type = "RedLine Payload"
		ruleset = "RedLine.yar"
		repository = "CAPESandbox/community"
		source_url = "https://github.com/CAPESandbox/community/blob/30a130d01407ba0f0637fb44e8159131a0c4e1e5/data/yara/CAPE/RedLine.yar"
		score = 75

	strings:
		$s1 = {2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 28 22 55 73 65 72 2d 41 67 65 6e 74 22 2c 22 20 28 20 22 20 4f 53 4e 61 6d 65 20 22 20 7c 20 22 20 62 69 74 20 22 20 7c 20 22 20 43 50 55 4e 41 6d 65 20 22 22}
		$s2 = {3a 3d 20 22 20 7c 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 22}
		$s3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 53 00 70 00 79 00 2e 00 61 00 68 00 6b 00}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}