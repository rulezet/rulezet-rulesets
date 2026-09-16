rule Win_Trojan_Silly_51
{
strings:
	$a0 = { 2a2e2a0032c9b44e8bd1cd21ba9e00b8023dcd21 }


condition:
	$a0
}