rule _Upack_v032_Beta_Patch__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.32 Beta (Patch) -> Sign by hot_UNP"
	strings:
		$0 = {BE 88 01 ?? ?? AD 50 ?? AD 91 F3 A5}
	condition:
		$0
}