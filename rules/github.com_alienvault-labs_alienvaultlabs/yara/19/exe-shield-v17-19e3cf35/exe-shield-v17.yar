rule _Exe_Shield_v17_
{
	meta:
		description = "Exe Shield v1.7"
	strings:
		$0 = {EB 06 68 F4 86 06 ?? C3 9C 60 E8}
	condition:
		$0 at entrypoint
}