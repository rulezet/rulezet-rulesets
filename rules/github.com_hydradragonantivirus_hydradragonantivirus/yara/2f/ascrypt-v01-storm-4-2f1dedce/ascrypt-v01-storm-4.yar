rule _AsCrypt_v01__SToRM__4_
{
	meta:
		description = "AsCrypt v0.1 -> SToRM - #4"
	strings:
		$0 = {80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 E2}
	condition:
		$0
}