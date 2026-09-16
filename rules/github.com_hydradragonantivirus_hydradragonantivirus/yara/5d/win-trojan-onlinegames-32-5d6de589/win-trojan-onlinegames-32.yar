rule Win_Trojan_Onlinegames_32
{
strings:
	$a0 = { 2f6d61696c312f6765742e617370 }

	$a1 = { 5c66662e696e69 }

	$a2 = { 5c742e696e69 }

	$a3 = { 474554 }

	$a4 = { 2e6c6f676f6e2e776f726c646f6677 }

	$a5 = { 6c6f67696e49643d }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}