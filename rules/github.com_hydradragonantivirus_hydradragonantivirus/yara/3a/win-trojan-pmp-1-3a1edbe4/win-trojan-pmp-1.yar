rule Win_Trojan_PMP_1
{
strings:
	$a0 = { 760d22019af4042201bff10b0e579acc0d22019af404220189ec5dc32c504d5020506172617369 }


condition:
	$a0
}