rule Win_Trojan_Tree2_1
{
strings:
	$a0 = { 81c775001e57e8eefde8b0fea1aaeb99bf6f089a1c024801ba2b00f7e28bf881c757001e }


condition:
	$a0
}