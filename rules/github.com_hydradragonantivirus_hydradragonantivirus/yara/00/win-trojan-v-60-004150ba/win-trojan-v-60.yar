rule Win_Trojan_V_60
{
strings:
	$a0 = { b430cd21be04008edec5440880fc1e720ab413cd2f1e52cd2f581fbff800ab8cd8ab8edec54440ab3d21018cd8ab06577507d1e6b90001f3a70e1f744bb452cd }


condition:
	$a0
}