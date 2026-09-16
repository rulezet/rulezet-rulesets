rule Win_Trojan_SillyC_242
{
strings:
	$a0 = { b41aba00fccd21b44ebaa20133c9cd21b8023dba1efccd218bd8 }


condition:
	$a0
}