rule Win_Trojan_Mini_16
{
strings:
	$a0 = { cd2193b43fb2719090fec65459cd21a31a010571009050b800429933c9cd2159b440fec6cd21 }


condition:
	$a0
}