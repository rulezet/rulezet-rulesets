rule Win_Trojan_ARCV_16
{
strings:
	$a0 = { 9804b87a0181370e1043434875f7e6100e4d8ffd1b11b1100f9db82b0c47080eabb483863614ba0ac331b6343bdd2f }


condition:
	$a0
}