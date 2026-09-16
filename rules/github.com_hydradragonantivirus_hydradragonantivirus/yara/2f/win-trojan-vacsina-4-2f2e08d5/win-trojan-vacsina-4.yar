rule Win_Trojan_Vacsina_4
{
strings:
	$a0 = { 1726c5b5000183c7048cdd26032e0801 }


condition:
	$a0
}