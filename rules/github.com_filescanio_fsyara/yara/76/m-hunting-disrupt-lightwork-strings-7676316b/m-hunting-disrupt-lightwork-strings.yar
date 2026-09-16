rule M_Hunting_Disrupt_LIGHTWORK_Strings : hardened limited
{
	meta:
		author = "Mandiant"
		description = "Searching for strings associated with IEC-104 used in LIGHTWORK."
		date = "2023-04-19"
		source = "https://cloud.google.com/blog/topics/threat-intelligence/cosmicenergy-ot-malware-russian-response/"
		score = 60

	strings:
		$s1 = {((43 6f 6e 6e 65 63 74 69 6e 67 20 74 6f 3a 20 25 73 3a 25 69 0a) | (43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 3a 00 20 00 25 00 73 00 3a 00 25 00 69 00 0a 00))}
		$s2 = {((43 6f 6e 6e 65 63 74 65 64 21) | (43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 21 00))}
		$s3 = {((53 65 6e 64 20 63 6f 6e 74 72 6f 6c 20 63 6f 6d 6d 61 6e 64 20 43 5f 53 43 5f 4e 41 5f 31) | (53 00 65 00 6e 00 64 00 20 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 43 00 5f 00 53 00 43 00 5f 00 4e 00 41 00 5f 00 31 00))}
		$s4 = {((43 6f 6e 6e 65 63 74 20 66 61 69 6c 65 64 21) | (43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 21 00))}
		$s5 = {((53 65 6e 64 20 74 69 6d 65 20 73 79 6e 63 20 63 6f 6d 6d 61 6e 64) | (53 00 65 00 6e 00 64 00 20 00 74 00 69 00 6d 00 65 00 20 00 73 00 79 00 6e 00 63 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00))}
		$s6 = {((57 61 69 74 20 2e 2e 2e) | (57 00 61 00 69 00 74 00 20 00 2e 00 2e 00 2e 00))}
		$s7 = {((65 78 69 74 20 30) | (65 00 78 00 69 00 74 00 20 00 30 00))}

	condition:
		filesize < 5MB and uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and all of them
}