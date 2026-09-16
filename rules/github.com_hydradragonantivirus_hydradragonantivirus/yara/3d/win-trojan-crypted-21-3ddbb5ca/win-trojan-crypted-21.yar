rule Win_Trojan_Crypted_21
{
strings:
	$a0 = { 6183ef4f606810784000ffd7b8001040003d007e400074068030????ebf3b800 }


condition:
	$a0
}