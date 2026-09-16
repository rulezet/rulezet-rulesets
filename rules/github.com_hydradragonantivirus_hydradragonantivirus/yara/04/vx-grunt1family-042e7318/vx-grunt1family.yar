import "pe"
rule _Vx_GRUNT1Family_
{
	meta:
		description = "Vx: GRUNT.1.Family"
	strings:
		$0 = {01 B9 ?? 00 31 17}
	condition:
		$0 at pe.entry_point
}