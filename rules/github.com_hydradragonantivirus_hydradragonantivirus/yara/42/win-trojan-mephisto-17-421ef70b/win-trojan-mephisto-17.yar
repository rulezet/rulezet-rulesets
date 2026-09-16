rule Win_Trojan_Mephisto_17
{
strings:
	$a0 = { a4cec1437c45bdc047005fd5ef6615818245c2a8f9bfdb8d864357211328d20d768362c670ff1aaa }


condition:
	$a0
}