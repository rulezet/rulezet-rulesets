rule Win_Trojan_Spanska_8
{
strings:
	$a0 = { 8becc7460200405d58cd21c3b43c33c9cd21c3b4 }


condition:
	$a0
}