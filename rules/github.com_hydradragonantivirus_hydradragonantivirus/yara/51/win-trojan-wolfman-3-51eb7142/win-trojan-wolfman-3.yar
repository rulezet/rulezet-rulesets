rule Win_Trojan_Wolfman_3
{
strings:
	$a0 = { 07cd1c83ec065883c4042d0400cc509cb10333c0bb0b008ec0b87725d3e326ff1f581e0781fb58447504e97b01eaccbb02008b2781ec00108ed4bcfeaf1eb9 }


condition:
	$a0
}