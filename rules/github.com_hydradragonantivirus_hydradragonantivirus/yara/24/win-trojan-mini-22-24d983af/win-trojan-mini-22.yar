rule Win_Trojan_Mini_22
{
strings:
	$a0 = { b106b440ba0001b9c40a2e8b1eb306e8edfc3dc40a741d2e8b1eb106b43ee8defc }


condition:
	$a0
}