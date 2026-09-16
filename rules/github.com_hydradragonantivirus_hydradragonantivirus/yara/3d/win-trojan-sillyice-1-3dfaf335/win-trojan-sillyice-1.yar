rule Win_Trojan_SillyIce_1
{
strings:
	$a0 = { 59003e898601012d03008945feb440b99f008d960001 }


condition:
	$a0
}