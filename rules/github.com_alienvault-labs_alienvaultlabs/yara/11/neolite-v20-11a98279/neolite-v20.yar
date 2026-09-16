rule _Neolite_v20_
{
	meta:
		description = "Neolite v2.0"
	strings:
		$0 = {9E 37 ?? ?? 48 6F 4C}
	condition:
		$0 at entrypoint
}