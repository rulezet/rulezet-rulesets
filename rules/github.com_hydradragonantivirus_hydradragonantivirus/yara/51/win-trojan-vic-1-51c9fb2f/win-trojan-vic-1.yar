rule Win_Trojan_Vic_1
{
strings:
	$a0 = { 9701582d03002ea39801b440ba9701b90300e849005a5983c91fb80157cd21b43ecd2159 }


condition:
	$a0
}