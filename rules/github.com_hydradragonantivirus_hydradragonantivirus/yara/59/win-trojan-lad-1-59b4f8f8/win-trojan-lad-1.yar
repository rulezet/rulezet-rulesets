rule Win_Trojan_Lad_1
{
strings:
	$a0 = { 609ceb215b57696e33322e41445420 }


condition:
	$a0
}