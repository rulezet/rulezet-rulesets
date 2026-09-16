rule Win_Trojan_RMNS_3
{
strings:
	$a0 = { 5e81ee0601e80300e97a00e902000700fabd0000bf8b0101f78b053d90907508b8f5f58905e92c00ba650301f2 }


condition:
	$a0
}