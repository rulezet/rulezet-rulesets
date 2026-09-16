rule Win_Trojan_Onlinegames_43
{
strings:
	$a0 = { f860908bc503c1f813c3e800000000159413000035a50c0000bf00000000c1d8 }


condition:
	$a0
}