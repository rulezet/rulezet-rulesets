rule _ASPack_v211c_
{
	meta:
		description = "ASPack v2.11c"
	strings:
		$0 = {60 E8 02 ?? ?? ?? EB 09 5D}
	condition:
		$0 at entrypoint
}