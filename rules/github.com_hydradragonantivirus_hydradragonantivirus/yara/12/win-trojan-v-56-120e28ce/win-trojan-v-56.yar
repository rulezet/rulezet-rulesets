rule Win_Trojan_V_56
{
strings:
	$a0 = { 04008edec55408b413cd2f1e52cd2f581fbff800ab8cd8ab8edec544403d2401ab8cd8ab06577509d1e6b9ff00f3a77447b452cd2106bef80026c47f12268b }


condition:
	$a0
}