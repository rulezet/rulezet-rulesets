rule Win_Trojan_ScreenMixer_1
{
strings:
	$a0 = { 0e500080f9307503e8d2fec39c2eff1e2800c32e803e41040074052eff2e42042ec6064104ff }


condition:
	$a0
}