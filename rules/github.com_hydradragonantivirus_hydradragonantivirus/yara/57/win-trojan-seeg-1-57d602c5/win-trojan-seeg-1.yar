rule Win_Trojan_Seeg_1
{
strings:
	$a0 = { 94f852a893d852a886e852a88df052a8a00052a89fe852a8a2d052a8985e52a897a652a89d1e4f26 }


condition:
	$a0
}