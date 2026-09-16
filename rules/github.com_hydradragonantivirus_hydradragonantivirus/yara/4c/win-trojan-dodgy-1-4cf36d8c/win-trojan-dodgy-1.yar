rule Win_Trojan_DODGY_1
{
strings:
	$a0 = { 02b80102e87802ebf206530e07b80103412e890e437c2e8916467cbb007ee85e025b0772d506 }


condition:
	$a0
}