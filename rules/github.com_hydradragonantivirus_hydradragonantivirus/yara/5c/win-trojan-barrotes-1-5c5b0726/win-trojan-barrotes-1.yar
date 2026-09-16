rule Win_Trojan_Barrotes_1
{
strings:
	$a0 = { 1c008d160301b440cd217210e87d00720bb967048d160001b440cd212e8b1e54012e8b164c }


condition:
	$a0
}