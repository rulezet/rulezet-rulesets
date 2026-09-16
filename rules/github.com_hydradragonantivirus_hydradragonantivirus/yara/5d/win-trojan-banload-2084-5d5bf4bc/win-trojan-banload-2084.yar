rule Win_Trojan_Banload_2084
{
strings:
	$a0 = { 66745c5741425c574142345c }

	$a1 = { 496e657455524c3a2f312e30 }

	$a2 = { 696d65[0-10]6f75742e657865 }

	$a3 = { 433a5c70757861646f722e657865 }


condition:
	$a0 and $a1 and $a2 and $a3
}