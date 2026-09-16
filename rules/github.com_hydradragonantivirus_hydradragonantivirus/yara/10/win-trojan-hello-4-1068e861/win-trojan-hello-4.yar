rule Win_Trojan_Hello_4
{
strings:
	$a0 = { 02ba0000b90000cd21b4408bd783ea03b9290190cd21be01002e897510b43ecd215ab44fcd2172 }


condition:
	$a0
}