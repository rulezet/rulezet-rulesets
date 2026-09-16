rule Win_Trojan_Trojan_220
{
strings:
	$a0 = { 41d5ed6869cc69cd0ae1d461cce85a5acd8bb76241f78861242bccde7245cb5dbf52786141cf }


condition:
	$a0
}