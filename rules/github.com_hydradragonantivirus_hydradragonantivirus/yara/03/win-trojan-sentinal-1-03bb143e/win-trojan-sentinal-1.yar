rule Win_Trojan_Sentinal_1
{
strings:
	$a0 = { 128c5ef455e816feb8f90f8bd08b46f22bc28946f28c }


condition:
	$a0
}