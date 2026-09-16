rule Win_Trojan_School1180_1
{
strings:
	$a0 = { 130426a11304d1e0d1e0d1e0d1e0d1e0d1e08ec033db06b80102ba0001b54fb111cd13b83c }


condition:
	$a0
}