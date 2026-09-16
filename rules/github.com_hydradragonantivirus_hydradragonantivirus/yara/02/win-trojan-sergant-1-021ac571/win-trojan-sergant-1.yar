rule Win_Trojan_Sergant_1
{
strings:
	$a0 = { 0500cd21e81500b440babc02b9e500cd21b43ecd215a595b }


condition:
	$a0
}