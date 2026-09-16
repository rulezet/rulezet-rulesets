rule Win_Trojan_Ohio_2
{
strings:
	$a0 = { 31d2b80902bb007ecd137205b8457c }


condition:
	$a0
}