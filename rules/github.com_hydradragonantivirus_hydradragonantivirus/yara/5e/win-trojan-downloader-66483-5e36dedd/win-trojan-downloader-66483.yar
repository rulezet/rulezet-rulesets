rule Win_Trojan_Downloader_66483
{
strings:
	$a0 = { 2f6765742e7068703f653d3539302674633d }

	$a1 = { 2f636e742e7068703f653d35393026753d }


condition:
	$a0 and $a1
}