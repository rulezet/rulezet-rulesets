rule _EncryptPE_V22006115__WFS_
{
	meta:
		description = "EncryptPE V2.2006.1.15 -> WFS"
	strings:
		$0 = {45 50 45 3A 20 45 6E 63 72 79 70 74 50 45 20 56 32 2E 32 30 30 36 2E 31 2E 31 35}
	condition:
		$0
}