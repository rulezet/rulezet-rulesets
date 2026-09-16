rule INDICATOR_SUSPICIOUS_EXE_RawGitHub_URL : refined hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing URLs to raw contents of a Github gist"
		score = 10

	strings:
		$url1 = {((68 74 74 70 73 3a 2f 2f 67 69 73 74 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f) | (68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 67 00 69 00 73 00 74 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00))}
		$url2 = {((68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f) | (68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 72 00 61 00 77 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00))}
		$raw = {((2f 72 61 77 2f) | (2f 00 72 00 61 00 77 00 2f 00))}

	condition:
		uint16( 0 ) == 0x5a4d and ( ( $url1 and $raw ) or ( $url2 ) )
}