import "pe"
rule _aPack_082_m_p_COM_
{
	meta:
		description = "aPack 0.82 -m -p [COM]"
	strings:
		$0 = {8C C8 05 00 00 8E C0 59 8E D0 51 BE AE 01 BF 00 01 50 57 FC B6 01 BD 7B 01 FF D5 73 5B FF D5 73 1C FF D5 73 3D BB 92 01 33 C9 FF D3 FF D3 FF D3 FF D3 8B D9 B1 01 85 DB 75 34 93 EB 36 E8 46 00 49 49 75 0A 2E 8B 1E 00 01 E8 3A 00 EB 20 49 AC}
	condition:
		$0 at pe.entry_point
}