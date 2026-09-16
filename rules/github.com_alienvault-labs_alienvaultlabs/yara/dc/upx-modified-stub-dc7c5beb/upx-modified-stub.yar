rule _UPX_Modified_stub_
{
	meta:
		description = "UPX Modified stub"
	strings:
		$0 = {EB EC 8A 06 46 88 07 47 01 DB 75}
	condition:
		$0 at entrypoint
}