rule Win_Trojan_Baba_7
{
strings:
	$a0 = { e8037c633d00fa775e2d03002ea39d012e803e9b010f744f8cc88ed8b44033d2b9b001cd2133c9 }


condition:
	$a0
}