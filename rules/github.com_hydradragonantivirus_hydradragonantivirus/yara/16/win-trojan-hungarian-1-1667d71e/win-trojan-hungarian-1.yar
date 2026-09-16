rule Win_Trojan_Hungarian_1
{
strings:
	$a0 = { d2cd21b9e20190ba0000b440cd21b801 }


condition:
	$a0
}