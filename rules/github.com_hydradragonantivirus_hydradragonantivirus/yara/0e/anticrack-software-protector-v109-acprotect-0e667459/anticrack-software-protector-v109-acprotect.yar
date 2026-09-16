rule _Anticrack_Software_Protector_v109_ACProtect_
{
	meta:
		description = "Anticrack Software Protector v1.09 (ACProtect)"
	strings:
		$0 = {60 E8 01 ?? ?? ?? ?? ??}
		$1 = {60 ?? ?? E8 01 ?? ?? ?? 83 04 24 06}
		$2 = {90}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}