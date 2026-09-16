rule INDICATOR_TOOL_DWAgent_SoundCapture : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detect DWAgent Remote Administration Tool Sound Capture Module"

	strings:
		$s1 = {44 57 41 53 6f 75 6e 64 43 61 70 74 75 72 65}
		$s2 = /_Z\d{2}DWASoundCapture/ ascii
		$s3 = {5f 5a 36 72 65 63 6f 72 64 50 76 53 5f}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}