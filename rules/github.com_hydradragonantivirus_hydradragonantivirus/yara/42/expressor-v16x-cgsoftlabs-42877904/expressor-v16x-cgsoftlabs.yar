import "pe"
rule _eXPressor_v16x__CGSoftLabs_
{
	meta:
		description = "eXPressor v1.6.x -> CGSoftLabs"
	strings:
		$0 = {68 92 24 49 00 C3 2B 15 CD E3 9E C0 CC 77 3F 49 AD BA F3 57 F2 9A 9F F3 08 F6 9C 84 E1 A9 E4 15 9B 98 60 40 2E E2 8C 4E A5 BF A0 E4 6A A1 70 FC A9 BB A6 85 81 FC FB EB 27 46 72 72 98 E6 5C 2C}
	condition:
		$0 at pe.entry_point
}