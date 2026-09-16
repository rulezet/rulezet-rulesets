rule _UPXHiT_v001__DJ_Siba_
{
	meta:
		description = "UPX$HiT v0.0.1 -> DJ Siba"
	strings:
		$0 = {94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61}
	condition:
		$0
}