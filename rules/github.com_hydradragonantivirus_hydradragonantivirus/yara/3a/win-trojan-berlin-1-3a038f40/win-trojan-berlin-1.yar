rule Win_Trojan_Berlin_1
{
strings:
	$a0 = { dc001dace881feb440b965030e1fba6703cc7221b8004233c933d2ccb440b91800baca00cc72 }


condition:
	$a0
}