rule Win_Trojan_Morordor_1
{
strings:
	$a0 = { 1fbf1a01803dba7410b95604bf1a010e1f8135af094747e2f6 }


condition:
	$a0
}