rule Win_Trojan_Peed_396
{
strings:
	$a0 = { 732bffd45589e551418b7d0c66abc1c80890c1c80866ab83ef0383ef01e2ea59 }


condition:
	$a0
}