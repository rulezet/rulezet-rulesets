import "pe"
rule _Armadillo_v3xx_
{
	meta:
		description = "Armadillo v3.xx"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58}
	condition:
		$0 at pe.entry_point
}