rule Win_Trojan_Small_5319
{
strings:
	$a0 = { d9edd7ecd039b8c921eb62e1fdad6f6441fe4da7aea94ef305af8e259f01b336635e63e17a42bc4b7c41c23fd844263606d6b432ce3fba6cf8f1e54683e9ed28b7ec29f0313269664473b0ddf928 }


condition:
	$a0
}