import "pe"
rule _CryptoLock_vV202_Eng__Ryan_Thian_
{
	meta:
		description = "Crypto-Lock vV2.02 (Eng) -> Ryan Thian"
	strings:
		$0 = {60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47}
	condition:
		$0 at pe.entry_point
}