rule Win_Trojan_Dialer_895
{
strings:
	$a0 = { 4942532d4469616c6572 }

	$a1 = { 726d73642e626174 }

	$a2 = { 4578706c6f7265725c4d61696e[0-3]50726f7879456e61626c65 }


condition:
	$a0 and $a1 and $a2
}