rule Win_Trojan__0046_0001_000_1
{
strings:
	$a0 = { 8bd1b80042cd2159030dba0001b440cd211fb80057cd21528bc133c2b90a0033d2f7f1f7e1 }


condition:
	$a0
}