rule Win_Trojan_Sterculius_6
{
strings:
	$a0 = { ba6102908bf2896c01eb07b91800baa60390b440e8dcfeb43ee8d7feb801435a1f59e8cefe }


condition:
	$a0
}