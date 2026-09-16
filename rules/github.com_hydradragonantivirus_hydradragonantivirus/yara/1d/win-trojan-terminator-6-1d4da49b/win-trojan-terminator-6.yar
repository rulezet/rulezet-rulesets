rule Win_Trojan_Terminator_6
{
strings:
	$a0 = { 028cca8edabad301b82125cd218cce }


condition:
	$a0
}