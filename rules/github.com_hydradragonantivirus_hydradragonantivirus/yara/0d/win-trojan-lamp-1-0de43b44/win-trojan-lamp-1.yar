rule Win_Trojan_Lamp_1
{
strings:
	$a0 = { c200b92e02b4408d960301cd21e88600fe86710380be71 }


condition:
	$a0
}