rule Win_Trojan_B_102
{
strings:
	$a0 = { 4646268834bb0002b80103cd131e0749b8010333dbcd130e07b8010333db }


condition:
	$a0
}