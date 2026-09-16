rule _FSG_v13_
{
	meta:
		description = "FSG v1.3"
	strings:
		$0 = {BB D0 01 40 ?? BF ?? 10 40 ?? BE 53 BB B2 80 A4 B6 80 FF D3 73 F9 33}
	condition:
		$0 at entrypoint
}