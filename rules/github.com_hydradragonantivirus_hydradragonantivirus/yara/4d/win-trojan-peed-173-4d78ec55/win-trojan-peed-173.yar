rule Win_Trojan_Peed_173
{
strings:
	$a0 = { 81c244321f0187ca7518f7db29dff7db01de89c3eb605589e5ad83ee0546c9c20800e87d00000068db95fdff56e8e4ff }


condition:
	$a0
}