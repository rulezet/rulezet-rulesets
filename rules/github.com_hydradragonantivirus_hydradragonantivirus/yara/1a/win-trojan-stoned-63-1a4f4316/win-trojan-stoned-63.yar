rule Win_Trojan_Stoned_63
{
strings:
	$a0 = { 02b101cd137238817f4e56a17431b80103b10850cd13587226fe0e0500750d }


condition:
	$a0
}