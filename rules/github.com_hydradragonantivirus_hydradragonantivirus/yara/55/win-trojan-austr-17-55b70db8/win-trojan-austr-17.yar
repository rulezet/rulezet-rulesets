rule Win_Trojan_Austr_17
{
strings:
	$a0 = { 01b440b9e201cd21b800422bd22bc9cd21b440b90400ba7901cd215a59 }


condition:
	$a0
}