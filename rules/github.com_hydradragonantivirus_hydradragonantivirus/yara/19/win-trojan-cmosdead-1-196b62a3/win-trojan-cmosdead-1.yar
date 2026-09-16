rule Win_Trojan_CmosDead_1
{
strings:
	$a0 = { 2e8b84a202f5b6440a1eccaba30200f8b1dc1216649fb8004cfcb674020efcf2cd21 }


condition:
	$a0
}