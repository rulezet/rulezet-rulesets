rule Win_Trojan_Trivial_324
{
strings:
	$a0 = { bc330181c10001890e3101ba290133c9b44ecd21585acd21 }


condition:
	$a0
}