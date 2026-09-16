rule Win_Trojan_Natas_12
{
strings:
	$a0 = { 1bf681cefd08f9f583de01ffc545f81186fe280bf679ef }


condition:
	$a0
}