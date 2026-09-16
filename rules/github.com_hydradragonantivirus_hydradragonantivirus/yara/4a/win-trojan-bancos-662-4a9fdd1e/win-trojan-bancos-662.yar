rule Win_Trojan_Bancos_662
{
strings:
	$a0 = { c2b2ca6fedcc2542b9dd1c46a4f0405328cf2eaf6dc1dddb07620cad2b8d28893e2b73dfaa85af526503aceddfcdc423c1ebd26f57ef616a5d1ad890a0e6be9fd6b7ec12 }


condition:
	$a0
}