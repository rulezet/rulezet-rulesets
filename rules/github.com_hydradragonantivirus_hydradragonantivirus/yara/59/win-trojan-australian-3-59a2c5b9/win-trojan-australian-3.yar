rule Win_Trojan_Australian_3
{
strings:
	$a0 = { ba6d540e1fbb49104331576d314f6d315f6de2f4 }


condition:
	$a0
}