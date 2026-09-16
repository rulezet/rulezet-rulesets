rule Win_Trojan_Small_4448
{
strings:
	$a0 = { 68????40008b042468800a000050e84b00000068????4000 }


condition:
	$a0
}