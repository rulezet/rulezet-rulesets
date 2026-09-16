rule Win_Trojan_Skid_1
{
strings:
	$a0 = { c707eb61b801039cff9c9f018d7f6126817d02b40d750d268b0526890733c0b99f01f3aa }


condition:
	$a0
}