import "pe"
rule _ExeBundle_v30_standard_loader_
{
	meta:
		description = "ExeBundle v3.0 (standard loader)"
	strings:
		$0 = {60 BE ?? F0 40 ?? 8D BE ?? 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 ?? ?? ??}
	condition:
		$0 at pe.entry_point
}