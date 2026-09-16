rule Win_Trojan_Vienna_28
{
strings:
	$a0 = { ac3c3b740a3c007403aaebf4be00005b1f89771280 }


condition:
	$a0
}