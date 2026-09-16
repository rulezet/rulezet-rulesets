rule Win_Trojan_June4_1
{
strings:
	$a0 = { 03bb0006e8500180fcff7546b80102bb007cb90b4fba0001e83c0180fcff7532b80103b90200 }


condition:
	$a0
}