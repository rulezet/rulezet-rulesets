rule Win_Trojan_BSMem_1
{
strings:
	$a0 = { 0103ba0000b90100bba001cd137215b80203ba0000b90800bba003cd137205b8004ccd210e }


condition:
	$a0
}