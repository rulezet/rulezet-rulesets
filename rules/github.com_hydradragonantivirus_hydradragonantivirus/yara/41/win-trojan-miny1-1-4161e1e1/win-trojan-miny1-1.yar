rule Win_Trojan_Miny1_1
{
strings:
	$a0 = { 45010f7208ba4a01b844f0cd21b409cd21b8234ccd2132c0cfe80f00b440ba0001b9b101cd21 }


condition:
	$a0
}