rule Win_Trojan_FuckOsama_1
{
strings:
	$a0 = { 203d2022676f6f64206c75636b206f6e2066696e64696e672074686174206e65 }


condition:
	$a0
}