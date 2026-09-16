rule Win_Trojan_Fakeav_28
{
strings:
	$a0 = { 29d252ff923040120085d27403c201008d0cd5060800006800d01b }

	$a1 = { 220d3940730b43b424c6b65c }

	$a2 = { 0a3a76541b304d }


condition:
	$a0 and $a1 and $a2
}