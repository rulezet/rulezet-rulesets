rule Win_Trojan_Gen_174
{
strings:
	$a0 = { 8bd78be8bc8be5fa3f9defe4c3fc46068bd68bda33c983cb84c7d4c98fc1268907c3c51f4608ea }


condition:
	$a0
}