rule Win_Trojan_Wra_1
{
strings:
	$a0 = { 72a181066a000301b440b902008d166a00cd21728e58050701505f8d15b440b9f400cd21727f }


condition:
	$a0
}