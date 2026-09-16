rule slvprot11
{
	meta:
		author = "PEiD"
		description = "SLVc0deProtector 1.1 -> SLV"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C }
	condition:
		$a0
}