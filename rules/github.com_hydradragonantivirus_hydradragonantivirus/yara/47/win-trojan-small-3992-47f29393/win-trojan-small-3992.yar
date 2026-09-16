rule Win_Trojan_Small_3992
{
strings:
	$a0 = { e82d00000009c0742889c281c2fe3141008d8a7cf400ff8d890010ff005231c005ffdfadde2902c1020f8d520439ca7e }


condition:
	$a0
}