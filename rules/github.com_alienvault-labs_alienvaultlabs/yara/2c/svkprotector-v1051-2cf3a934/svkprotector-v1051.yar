rule _SVKProtector_v1051_
{
	meta:
		description = "SVK-Protector v1.051"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? EB 05 B8 06 36 42 ?? 64 A0}
	condition:
		$0 at entrypoint
}