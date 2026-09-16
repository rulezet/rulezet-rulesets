rule Win_Trojan_Genesis_7
{
strings:
	$a0 = { 07008d963a04e8e10080bef50703730ab43b8d964004cd2173e88db6b407c6045c }


condition:
	$a0
}