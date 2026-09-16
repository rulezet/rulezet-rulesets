rule Win_Trojan_Animus_1
{
strings:
	$a0 = { 3f1e57bfbe3f1e57bf02401e57bf0c401e579ad501 }


condition:
	$a0
}