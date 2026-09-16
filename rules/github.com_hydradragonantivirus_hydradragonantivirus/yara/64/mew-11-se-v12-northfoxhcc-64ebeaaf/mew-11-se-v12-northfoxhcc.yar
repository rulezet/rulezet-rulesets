import "pe"
rule _MEW_11_SE_v12__NorthfoxHCC_
{
	meta:
		description = "MEW 11 SE v1.2 -> Northfox[HCC]"
	strings:
		$0 = {E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? ?? 00}
	condition:
		$0 at pe.entry_point
}