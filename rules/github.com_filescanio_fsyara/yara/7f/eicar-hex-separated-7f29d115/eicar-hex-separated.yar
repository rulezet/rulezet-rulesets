rule EICAR_Hex_Separated : hardened
{
	meta:
		author = "filescan.io"
		description = "Detects hex-encoded EICAR test string with byte separators, as produced by hexdump/xxd/CyberChef"
		score = 75

	strings:
		$a = /58[-, ;:]35[-, ;:]4f[-, ;:]21[-, ;:]50[-, ;:]25[-, ;:]40[-, ;:]41[-, ;:]50[-, ;:]5b[-, ;:]34[-, ;:]5c/ nocase ascii wide

	condition:
		any of them
}