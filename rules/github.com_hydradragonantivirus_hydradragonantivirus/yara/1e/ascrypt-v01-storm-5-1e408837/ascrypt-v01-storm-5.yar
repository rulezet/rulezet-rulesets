rule _AsCrypt_v01__SToRM__5_
{
	meta:
		description = "AsCrypt v0.1 -> SToRM - #5"
	strings:
		$0 = {83 ?? ?? E2 ?? ?? E2 ?? FF}
	condition:
		$0
}