import "pe"
rule _CodeLock_vxx__RTSoft_
{
	meta:
		description = "Code-Lock vx.x -> RTSoft."
	strings:
		$0 = {43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00}
	condition:
		$0 at pe.entry_point
}