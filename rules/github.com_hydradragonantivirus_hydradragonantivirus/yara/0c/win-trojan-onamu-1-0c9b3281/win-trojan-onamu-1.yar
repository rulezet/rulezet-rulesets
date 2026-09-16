rule Win_Trojan_Onamu_1
{
strings:
	$a0 = { 609ce8000000005d8bc581ed9a10400085ed75072d9a000000eb05 }


condition:
	$a0
}