rule Win_Trojan_E_26
{
strings:
	$a0 = { dab40dcd21bb00024a8bfab8024acd2fbb06003bfa750939162a03bf00f9753ae8ccfff32ea4b060e664e464a8 }


condition:
	$a0
}