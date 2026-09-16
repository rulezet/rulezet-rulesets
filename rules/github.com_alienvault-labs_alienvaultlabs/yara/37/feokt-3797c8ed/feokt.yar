rule _Feokt_
{
	meta:
		description = "Feokt"
	strings:
		$0 = {55 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? BE ?? ?? ?? 03 F5 BA ?? ?? 2B D5 8B DD 33 C0 AC 3C ?? 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F}
	condition:
		$0 at entrypoint
}