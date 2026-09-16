rule Win_Trojan_Peed_33
{
strings:
	$a0 = { 29db81ebe0a140006800020000f7db8b0418ffd052682a335f04e86900000089 }


condition:
	$a0
}