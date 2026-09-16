rule Win_Trojan_DM_1
{
strings:
	$a0 = { 8bde8037??43e2fac3be????bf000157a5a533c08ec081c7030126803d??740a81ee????e8d6ff }


condition:
	$a0
}