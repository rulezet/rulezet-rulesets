rule Win_Trojan_Mini_4
{
strings:
	$a0 = { 2193b43fb26afec65459cd21a31801056a0050b800429933c9cd2159b440fec6cd21b43ecd }


condition:
	$a0
}