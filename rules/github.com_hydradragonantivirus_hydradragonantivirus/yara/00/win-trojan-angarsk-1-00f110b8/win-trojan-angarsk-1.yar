rule Win_Trojan_Angarsk_1
{
strings:
	$a0 = { 8d568890b93f00cd21721a8d96cd00b8023dcd217209 }


condition:
	$a0
}