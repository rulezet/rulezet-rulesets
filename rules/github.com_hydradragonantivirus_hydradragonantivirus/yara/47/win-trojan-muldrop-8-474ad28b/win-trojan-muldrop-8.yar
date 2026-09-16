rule Win_Trojan_MulDrop_8
{
strings:
	$a0 = { 6683ea7a01c6bf00000000c1cf04648b174e81c2040000006683e8c28b0a01f2b8c8c5ff2ac1c00131 }


condition:
	$a0
}