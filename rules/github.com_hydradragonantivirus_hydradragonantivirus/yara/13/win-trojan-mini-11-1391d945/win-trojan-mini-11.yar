rule Win_Trojan_Mini_11
{
strings:
	$a0 = { cd2193b43fb2669090fec65459cd21a319010566009050b800429933c9cd2159b440fec6cd21 }


condition:
	$a0
}