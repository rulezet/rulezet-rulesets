rule Win_Trojan_TeaForTwo_1
{
strings:
	$a0 = { 1e0c06a30e06b8901ad1e040cd218cc0891e1006a31206b88912d1e040baca00cd21b89012d1e0 }


condition:
	$a0
}