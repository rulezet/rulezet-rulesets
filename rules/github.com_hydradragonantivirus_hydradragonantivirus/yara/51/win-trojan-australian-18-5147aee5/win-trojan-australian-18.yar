rule Win_Trojan_Australian_18
{
strings:
	$a0 = { b6f001bf000157a5a4b8a054cd213d0712743f1e58488ec08b1e020081eb1500891e020026812e0300150083 }


condition:
	$a0
}