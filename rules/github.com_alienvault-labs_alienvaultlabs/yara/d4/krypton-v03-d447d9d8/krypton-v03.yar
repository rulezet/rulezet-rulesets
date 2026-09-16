rule _Krypton_v03_
{
	meta:
		description = "Krypton v0.3"
	strings:
		$0 = {54 E8 5D 8B C5 81 ED 61 34 2B 85 60 37 83 E8}
	condition:
		$0 at entrypoint
}