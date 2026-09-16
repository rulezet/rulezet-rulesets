rule Win_Trojan_Voice_1
{
strings:
	$a0 = { 068bc0e800005b81eb09018bcb2ef6970001be000103f3bf00008bd78ec71e8cc88ed8fcb920005657f3a65f5e }


condition:
	$a0
}