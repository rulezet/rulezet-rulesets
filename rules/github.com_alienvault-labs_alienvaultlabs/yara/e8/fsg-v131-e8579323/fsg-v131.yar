rule _FSG_v131_
{
	meta:
		description = "FSG v1.31"
	strings:
		$0 = {BE A4 01 40 ?? AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13}
	condition:
		$0 at entrypoint
}