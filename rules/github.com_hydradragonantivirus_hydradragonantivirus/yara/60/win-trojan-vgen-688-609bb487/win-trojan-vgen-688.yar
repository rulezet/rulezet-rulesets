rule Win_Trojan_VGEN_688
{
strings:
	$a0 = { c1c40390458bc990fdf981c71f0126f88135502afc4dfc479047e2f32e45e82a6c90072b9d0bc379ee2a5195f622e9 }


condition:
	$a0
}