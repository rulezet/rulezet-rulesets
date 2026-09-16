rule Win_Trojan__0230_0006_000_1
{
strings:
	$a0 = { 46e2fbb440b9640433d2061f9c2eff1ee003723db4499c2eff1ee003b80042998bca9c2eff1e }


condition:
	$a0
}