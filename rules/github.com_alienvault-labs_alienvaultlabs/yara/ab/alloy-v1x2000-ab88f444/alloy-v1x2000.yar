rule _Alloy_v1x2000_
{
	meta:
		description = "Alloy v1.x.2000"
	strings:
		$0 = {52 31 C0 E8 FF FF FF}
	condition:
		$0 at entrypoint
}