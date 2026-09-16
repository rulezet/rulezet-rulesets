rule _ASPack_v2001_
{
	meta:
		description = "ASPack v2.001"
	strings:
		$0 = {60 E8 72 05 ?? ?? EB 33 87 DB}
	condition:
		$0 at entrypoint
}