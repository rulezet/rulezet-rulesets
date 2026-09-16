rule Win_Trojan_Trojan_879
{
strings:
	$a0 = { 3c3f706870202f2a2a2f206576616c286261736536345f6465636f64652822 }

	$a1 = { 2229293b }


condition:
	$a0 and $a1
}