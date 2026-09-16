rule Win_Trojan_IRC_39
{
strings:
	$a0 = { 4d5a666172627261757363685045[0-200]6c696265726174655738b7 }


condition:
	$a0
}