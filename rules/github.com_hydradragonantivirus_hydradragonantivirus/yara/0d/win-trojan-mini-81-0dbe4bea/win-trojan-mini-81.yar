rule Win_Trojan_Mini_81
{
strings:
	$a0 = { 21722493061f8bd7b43fb9ffffcd21803d80740f03c750b800429941cd2159b440cd21b43ecd21 }


condition:
	$a0
}