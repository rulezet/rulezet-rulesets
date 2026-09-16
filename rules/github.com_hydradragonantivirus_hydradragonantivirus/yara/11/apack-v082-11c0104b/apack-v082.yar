import "pe"
rule _aPack_v082_
{
	meta:
		description = "aPack v0.82"
	strings:
		$0 = {1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB}
	condition:
		$0 at pe.entry_point
}