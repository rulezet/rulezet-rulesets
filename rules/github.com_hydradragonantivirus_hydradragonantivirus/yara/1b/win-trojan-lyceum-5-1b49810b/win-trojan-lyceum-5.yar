rule Win_Trojan_Lyceum_5
{
strings:
	$a0 = { ee03fc5053b8bbaacd213d62197502eb3c1e068cc0488ec0bb030026832f5c4b8b072d5c0089078ec00e1f5633ff }


condition:
	$a0
}