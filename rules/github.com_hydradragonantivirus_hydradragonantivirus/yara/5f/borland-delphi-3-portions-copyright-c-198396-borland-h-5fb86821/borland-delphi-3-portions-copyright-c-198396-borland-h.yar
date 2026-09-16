rule _Borland_Delphi_3__Portions_Copyright_c_198396_Borland_h_
{
	meta:
		description = "Borland Delphi 3 -> Portions Copyright (c) 1983,96 Borland (h)"
	strings:
		$0 = {50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 36 20 42 6F 72 6C 61 6E 64 00}
	condition:
		$0
}