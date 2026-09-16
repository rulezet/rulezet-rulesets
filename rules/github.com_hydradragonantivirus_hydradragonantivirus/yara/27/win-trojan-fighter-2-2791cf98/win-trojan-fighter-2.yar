rule Win_Trojan_Fighter_2
{
strings:
	$a0 = { 51ffc53e014d751181fd3f750c81fd587507592f002f5219 }


condition:
	$a0
}