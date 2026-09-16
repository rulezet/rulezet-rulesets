rule _XPack_v142_
{
	meta:
		description = "X-Pack v1.4.2"
	strings:
		$0 = {72 ?? C3 8B DE 83 ?? ?? C1 ?? ?? 8C D8 03 C3 8E D8 8B DF 83 ?? ?? C1 ?? ?? 8C C0 03 C3 8E C0 C3}
	condition:
		$0
}