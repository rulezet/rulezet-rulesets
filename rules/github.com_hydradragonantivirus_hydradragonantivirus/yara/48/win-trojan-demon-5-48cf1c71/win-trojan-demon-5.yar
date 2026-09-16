rule Win_Trojan_Demon_5
{
strings:
	$a0 = { d2e89a00ba3f02b440b90300cd21ff363d02c7063d020000e87900b440b96301ba0001cd21 }


condition:
	$a0
}