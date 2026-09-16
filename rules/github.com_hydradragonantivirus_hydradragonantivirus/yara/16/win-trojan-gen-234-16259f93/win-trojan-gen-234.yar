rule Win_Trojan_Gen_234
{
strings:
	$a0 = { fc40fc8934d4fca20ffcbc0ae9ba509103b805003d0b985bb91501a11f8cfc16f9fe0ae104 }


condition:
	$a0
}