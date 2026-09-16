rule Win_Trojan_Renegade_2
{
strings:
	$a0 = { 9cfa2eff1e7b11e807002ec606770000c39c515657b9af10becb008b3e7500313c4647e2fa }


condition:
	$a0
}