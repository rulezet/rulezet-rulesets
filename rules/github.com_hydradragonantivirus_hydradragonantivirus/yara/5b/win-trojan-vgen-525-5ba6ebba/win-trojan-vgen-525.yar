rule Win_Trojan_VGEN_525
{
strings:
	$a0 = { 2abf00018bf283c609b90300f3a4528bfa8bc7057b002d080050c38bd783c253b409cd212e9c589eb40972295a52 }


condition:
	$a0
}