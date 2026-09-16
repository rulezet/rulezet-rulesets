rule masm32_tasm32
{
	meta:
		author = "PEiD"
		description = "MASM32 / TASM32"
		group = "20"
		function = "0"
	strings:
		$a0 = { 6A ?? E8 ?? ?? ?? ?? A3 }
	condition:
		$a0
}