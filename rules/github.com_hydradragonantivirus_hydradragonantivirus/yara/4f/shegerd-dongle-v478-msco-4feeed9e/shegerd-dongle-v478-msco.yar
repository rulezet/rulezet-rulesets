import "pe"
rule _Shegerd_Dongle_V478__MSCo_
{
	meta:
		description = "Shegerd Dongle V4.78 -> MS.Co."
	strings:
		$0 = {E8 32 00 00 00 B8 ?? ?? ?? ?? 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C}
	condition:
		$0 at pe.entry_point
}