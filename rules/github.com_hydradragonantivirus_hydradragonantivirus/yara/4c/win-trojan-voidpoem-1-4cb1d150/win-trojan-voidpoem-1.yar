rule Win_Trojan_VoidPoem_1
{
strings:
	$a0 = { b9cb04302547e2fbbad504b80125cd210402cd21c3 }


condition:
	$a0
}