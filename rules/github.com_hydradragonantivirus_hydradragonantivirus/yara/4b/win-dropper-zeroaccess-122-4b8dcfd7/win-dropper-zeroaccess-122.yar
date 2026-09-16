rule Win_Dropper_ZeroAccess_122
{
strings:
	$a0 = { 8b028d520433055020400089018d4904ff4c24??75ea }


condition:
	$a0
}