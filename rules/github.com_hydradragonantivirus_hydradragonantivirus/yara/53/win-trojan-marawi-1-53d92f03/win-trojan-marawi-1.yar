rule Win_Trojan_Marawi_1
{
strings:
	$a0 = { 9dc60eb6b62ee658468e58d5aeb6defebe4e58fd4e9e4e8e4ee658dee658352e3e2eee462ec658d0 }


condition:
	$a0
}