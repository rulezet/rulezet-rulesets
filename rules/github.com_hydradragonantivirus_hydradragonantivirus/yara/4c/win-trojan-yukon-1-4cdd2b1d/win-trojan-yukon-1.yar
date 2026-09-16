rule Win_Trojan_Yukon_1
{
strings:
	$a0 = { 5a01b43bcd21ba5c01b41acd218d165401b90000b44ecd21b43db001ba7a01cd218bd8b457b000cd215152b440b9970090ba0001cd21b457b0015a59cd21b4 }


condition:
	$a0
}