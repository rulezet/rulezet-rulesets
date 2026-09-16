rule Win_Trojan_Mvm_1
{
strings:
	$a0 = { c1c0a4dba9c48d81898ec5a9c2a6e4c6a492ecedd8e6a492a70240a74e41c5c6c7aac9fa81b5b4af8fb0a5aed2a9c2a6e4c7aac9fa81b5b4af8fb0a5aed2acc1c0a4dadb }


condition:
	$a0
}