rule Win_Trojan_Problem_8
{
strings:
	$a0 = { 33ed559d83ec022ec606eb002e5d83fd00753280fc }


condition:
	$a0
}