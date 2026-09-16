rule Win_Trojan_Gen_124
{
strings:
	$a0 = { d5a17505b80d909dcf2eff36 }


condition:
	$a0
}