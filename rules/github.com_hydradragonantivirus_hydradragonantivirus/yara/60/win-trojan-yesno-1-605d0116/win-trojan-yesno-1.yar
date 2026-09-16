rule Win_Trojan_YesNo_1
{
strings:
	$a0 = { 8cca8edaba07005b9cfa2eff1e2300fb518cca8edaba0000b95e0390b4409cfa2eff1e2300fb }


condition:
	$a0
}