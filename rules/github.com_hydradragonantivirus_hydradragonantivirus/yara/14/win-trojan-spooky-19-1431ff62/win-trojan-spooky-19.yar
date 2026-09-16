rule Win_Trojan_Spooky_19
{
strings:
	$a0 = { ac5188c180f1??88c859aae2f3c3 }


condition:
	$a0
}