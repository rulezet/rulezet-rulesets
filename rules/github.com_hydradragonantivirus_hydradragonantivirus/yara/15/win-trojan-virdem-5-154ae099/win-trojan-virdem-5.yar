rule Win_Trojan_Virdem_5
{
strings:
	$a0 = { 1c26c707205c431e8cc08ed88bd3 }


condition:
	$a0
}