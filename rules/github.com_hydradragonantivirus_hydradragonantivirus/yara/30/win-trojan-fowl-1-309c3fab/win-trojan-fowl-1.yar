rule Win_Trojan_Fowl_1
{
strings:
	$a0 = { 0e1fcd12b106d3e02d401f508ec0b8410050bb3e0081c3007c5381c34600b805028b0f8b57 }


condition:
	$a0
}