rule Win_Trojan_Kemerovo_3
{
strings:
	$a0 = { 8bf8b90400a4e2fd8bfa2bda81eb }


condition:
	$a0
}