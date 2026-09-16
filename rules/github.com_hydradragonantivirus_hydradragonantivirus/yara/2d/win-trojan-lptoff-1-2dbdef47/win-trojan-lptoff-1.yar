rule Win_Trojan_LptOff_1
{
strings:
	$a0 = { 5257561e06e800005e81c6f4000e07bf0001a4a5b820008ec033ff26803d51742fb900012bf1fcf3a433c08ed8c706 }


condition:
	$a0
}