rule Win_Trojan_Lauren_1
{
strings:
	$a0 = { 028dbe2201f6159c0ee81100e2f7c3e8ecff5a5958cd }


condition:
	$a0
}