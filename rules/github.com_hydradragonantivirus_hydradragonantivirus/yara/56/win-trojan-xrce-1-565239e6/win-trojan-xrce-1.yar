rule Win_Trojan_Xrce_1
{
strings:
	$a0 = { 8bec8b6efafb4d4dfcb80c0ccd212d49487403e84e00b462cd218ec38edb8cc83bc3742383c3102e019e43002e03 }


condition:
	$a0
}