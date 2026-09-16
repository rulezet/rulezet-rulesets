rule Win_Trojan_Shutdown_8
{
strings:
	$a0 = { 406563686f206f66662073687574646f776e202d73202d66202d742031 }


condition:
	$a0
}