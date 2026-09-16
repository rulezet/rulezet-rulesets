rule Win_Trojan_V_61
{
strings:
	$a0 = { 2180fc1ebe04008edec54408720ab413cd2f1e52cd2f581fbff800ab8cd8ab8edec54440ab3d21018cd8ab06577507d1e6b90001f3a70e1f744ab452cd }


condition:
	$a0
}