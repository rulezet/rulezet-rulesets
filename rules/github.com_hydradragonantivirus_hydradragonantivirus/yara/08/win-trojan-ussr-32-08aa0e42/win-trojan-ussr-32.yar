rule Win_Trojan_USSR_32
{
strings:
	$a0 = { 161200f6d63ad674b4b8024233c933d2cd21 }


condition:
	$a0
}