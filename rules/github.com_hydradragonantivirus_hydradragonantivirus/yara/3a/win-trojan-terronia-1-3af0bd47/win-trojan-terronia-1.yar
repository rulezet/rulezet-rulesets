rule Win_Trojan_Terronia_1
{
strings:
	$a0 = { 2e802c??b9a00f464ee2fc4e81fe????75ee }


condition:
	$a0
}