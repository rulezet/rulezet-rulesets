rule _CDCops_II_
{
	meta:
		description = "CD-Cops II"
	strings:
		$0 = {E9 C5 02 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7}
	condition:
		$0 at entrypoint
}