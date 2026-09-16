rule Win_Trojan_Anti_24
{
strings:
	$a0 = { 0100ba8000cd135381c3be01b904003817740883c310e2f7e9b400b801028a77018b4f025bcd13 }


condition:
	$a0
}