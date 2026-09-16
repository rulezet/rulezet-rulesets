rule Win_Trojan_Trojan_78
{
strings:
	$a0 = { 40bab812b90012e869f933c02689451526894517b440ba7612b91a00e854f9b801578b0e5a128b }


condition:
	$a0
}