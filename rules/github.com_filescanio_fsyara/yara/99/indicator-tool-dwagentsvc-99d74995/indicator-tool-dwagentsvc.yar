rule INDICATOR_TOOL_DWAgentSVC : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detect DWAgent Remote Administration Tool service"

	strings:
		$s1 = {5c 00 6e 00 61 00 74 00 69 00 76 00 65 00 5c 00 64 00 77 00 61 00 67 00 75 00 70 00 64 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {5c 00 6e 00 61 00 74 00 69 00 76 00 65 00 5c 00 64 00 77 00 61 00 67 00 73 00 76 00 63 00 2e 00 65 00 78 00 65 00 22 00 20 00 72 00 75 00 6e 00}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 72 65 61 74 65 53 65 72 76 69 63 65 57 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = /dwagent\.(pid|start|stop)/ wide
		$s5 = {43 00 68 00 65 00 63 00 6b 00 20 00 75 00 70 00 64 00 61 00 74 00 69 00 6e 00 67 00 2e 00 2e 00 2e 00}

	condition:
		uint16( 0 ) == 0x5a4d and 4 of them
}