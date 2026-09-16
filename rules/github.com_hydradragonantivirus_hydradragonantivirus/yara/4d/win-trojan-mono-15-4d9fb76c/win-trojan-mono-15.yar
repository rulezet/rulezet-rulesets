rule Win_Trojan_Mono_15
{
strings:
	$a0 = { 908bc9908bc9908bc9908bc9908bc9908bc990908bc9908bc99090908bc9908bc9908bc9908bc9908bc99090908bc9908bc990 }


condition:
	$a0
}