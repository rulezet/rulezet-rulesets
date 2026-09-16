import "pe"
rule _Mew_10_V10_Eng__Northfox_
{
	meta:
		description = "Mew 10 V1.0 (Eng) -> Northfox"
	strings:
		$0 = {33 C0 E9 ?? ?? FF FF}
	condition:
		$0 at pe.entry_point
}