rule Win_Trojan_Small_4449
{
strings:
	$a0 = { 6a00810424??3042008d1c240f6e1b0f7edb89d8ba18dafe0f525068 }


condition:
	$a0
}