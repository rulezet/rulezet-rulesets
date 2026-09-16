rule Win_Trojan_Badless_1
{
strings:
	$a0 = { 40b9f302ba05012bca8d960501cd217240b801578b8e470180be4901ff740380c90f8b964501cd }


condition:
	$a0
}