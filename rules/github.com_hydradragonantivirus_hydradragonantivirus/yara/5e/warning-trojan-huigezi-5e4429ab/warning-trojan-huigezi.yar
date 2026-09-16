import "pe"
rule _WARNING__TROJAN__HuiGeZi_
{
	meta:
		description = "WARNING -> TROJAN -> HuiGeZi"
	strings:
		$0 = {55 8B EC 81 C4 ?? FE FF FF 53 56 57 33 C0 89 85 ?? FE FF FF}
	condition:
		$0 at pe.entry_point
}