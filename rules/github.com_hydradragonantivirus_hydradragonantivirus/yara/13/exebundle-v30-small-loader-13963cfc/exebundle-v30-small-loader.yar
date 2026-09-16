import "pe"
rule _ExeBundle_v30_small_loader_
{
	meta:
		description = "ExeBundle v3.0 (small loader)"
	strings:
		$0 = {65 78 65 73 68 6C 2E 64 6C 6C C0}
	condition:
		$0 at pe.entry_point
}