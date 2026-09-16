rule Win_Trojan__0320_25199_000_1
{
strings:
	$a0 = { b80242e84e00b440ba3efeb9e30090cd217213b80042e83b00b440ba0001b9e30090cd2172 }


condition:
	$a0
}