rule _SoftSentry_v211_
{
	meta:
		description = "SoftSentry v2.11"
	strings:
		$0 = {55 8B EC 83 EC 53 56 57 E9 B0}
	condition:
		$0 at entrypoint
}