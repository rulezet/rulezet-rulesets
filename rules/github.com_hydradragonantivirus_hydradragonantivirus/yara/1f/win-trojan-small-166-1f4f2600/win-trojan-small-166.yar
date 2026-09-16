rule Win_Trojan_Small_166
{
strings:
	$a0 = { 4b741480fc77755683c408581e578b36b90103f7f3a4 }


condition:
	$a0
}