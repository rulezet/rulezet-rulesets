rule Win_Trojan_Mit_1
{
strings:
	$a0 = { 21b405b002b500b600b280cd13b406cd13b405b200cd13b44ccd218b0e320181e9e001890ede02 }


condition:
	$a0
}