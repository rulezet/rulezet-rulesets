rule Win_Trojan_Sterculius_8
{
strings:
	$a0 = { 02908bf2896c01eb07b91800bab60390b440e8d4fe595ab80157e8ccfeb43ee8c7feb801435a }


condition:
	$a0
}