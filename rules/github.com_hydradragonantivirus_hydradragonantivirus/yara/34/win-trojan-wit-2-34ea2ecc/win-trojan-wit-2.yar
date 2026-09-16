rule Win_Trojan_Wit_2
{
strings:
	$a0 = { 22018a3c33c09e9f86c40405e800005f03f8ffe78af880f7 }


condition:
	$a0
}