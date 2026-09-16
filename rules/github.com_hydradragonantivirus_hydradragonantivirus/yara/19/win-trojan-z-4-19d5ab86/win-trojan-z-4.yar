rule Win_Trojan_Z_4
{
strings:
	$a0 = { 6a40680030000068003001006800009d4bffd009c00f84ac73ffffbf00209d4b55b9000001005efcf3a4e864b6ffff }


condition:
	$a0
}