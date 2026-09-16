import "pe"
rule _Vx_Kuku448_
{
	meta:
		description = "Vx: Kuku.448"
	strings:
		$0 = {AE 75 ED E2 F8 89 3E ?? ?? BA ?? ?? 0E 07 BF ?? ?? EB}
	condition:
		$0 at pe.entry_point
}