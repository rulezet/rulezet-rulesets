rule Win_Trojan_PS_31
{
strings:
	$a0 = { 14b9ca008137312283ebfee2f7d922317fb0cf2423bc9445268565a8ef10962bafa76a35ef109a1517fc03377189 }


condition:
	$a0
}