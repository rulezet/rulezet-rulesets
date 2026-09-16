rule Win_Trojan_Small_5404
{
strings:
	$a0 = { 6a606810b54000e80e160000bf940000008bc7e81a0200008965e88bf4893e56ff15 }


condition:
	$a0
}