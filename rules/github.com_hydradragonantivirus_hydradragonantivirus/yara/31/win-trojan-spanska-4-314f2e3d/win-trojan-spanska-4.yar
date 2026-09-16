rule Win_Trojan_Spanska_4
{
strings:
	$a0 = { 47c38a962101b934048db63b018bfeac32c2e8e9ffe2f8 }


condition:
	$a0
}