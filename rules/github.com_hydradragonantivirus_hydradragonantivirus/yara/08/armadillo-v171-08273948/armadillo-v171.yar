import "pe"
rule _Armadillo_v171_
{
	meta:
		description = "Armadillo v1.71"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1}
	condition:
		$0 at pe.entry_point
}