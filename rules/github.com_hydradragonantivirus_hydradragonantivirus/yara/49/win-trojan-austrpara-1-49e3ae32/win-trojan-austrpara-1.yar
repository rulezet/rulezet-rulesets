rule Win_Trojan_AustrPara_1
{
strings:
	$a0 = { b440b198b601cd21b8004233d233c9cd21b440b601b104cd21b43ecd21 }


condition:
	$a0
}