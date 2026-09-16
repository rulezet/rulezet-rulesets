import "pe"
rule _aPack_v098b_COM_
{
	meta:
		description = "aPack v0.98b [COM]"
	strings:
		$0 = {BE ?? ?? BF ?? ?? 8B CF FC 57 F3 A4 C3 BF ?? ?? 57 57 BE ?? ?? B2 ?? BD ?? ?? 50 A4}
	condition:
		$0 at pe.entry_point
}