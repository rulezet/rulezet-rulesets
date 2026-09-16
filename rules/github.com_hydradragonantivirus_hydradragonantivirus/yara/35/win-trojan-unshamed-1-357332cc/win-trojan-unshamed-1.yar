rule Win_Trojan_Unshamed_1
{
strings:
	$a0 = { 31ff8ed78edfbc007c89e6b106ff8c13888b841388d3e0b900018ec0fcadabe2fcb80900be8101 }


condition:
	$a0
}