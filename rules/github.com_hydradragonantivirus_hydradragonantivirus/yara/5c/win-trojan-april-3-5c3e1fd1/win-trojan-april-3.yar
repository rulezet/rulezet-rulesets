rule Win_Trojan_April_3
{
strings:
	$a0 = { c0e80b00b80502b90300e8020007cb505850bd0300ba8000cd1373072bc0cd134d75ed58c3 }


condition:
	$a0
}