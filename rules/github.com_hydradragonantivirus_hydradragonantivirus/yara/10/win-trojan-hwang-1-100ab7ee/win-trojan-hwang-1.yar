rule Win_Trojan_Hwang_1
{
strings:
	$a0 = { 578b1e0a008b0e26008b162800cd21c3b4408b1e0a00b9e5058d1600001e061fcd211fc3e9 }


condition:
	$a0
}