rule Win_Trojan_Chespirito_1
{
strings:
	$a0 = { 5e82ee0a028eb7ca02c00102a6a68e97ce02b51bce22b54f34ca8e97c402ce227429b51bbb8101ce }


condition:
	$a0
}