rule _SoftSentry_v30_
{
	meta:
		description = "SoftSentry v3.0"
	strings:
		$0 = {52 53 51 56 57 55 E8 5D 81 ED 36 E8 01 60 BA E8}
	condition:
		$0 at entrypoint
}