rule Win_Trojan_Agent_33361
{
strings:
	$a0 = { 06bdff1d52cf945ad514ffffb0ce938b06bc0e56317dcefb33f7df741072bae70765e989d09632b2fa025b5bff831c6d80a88edf539d780c39eb8a5f1c210bb9433a764a703e2d176291f0dd13de }


condition:
	$a0
}