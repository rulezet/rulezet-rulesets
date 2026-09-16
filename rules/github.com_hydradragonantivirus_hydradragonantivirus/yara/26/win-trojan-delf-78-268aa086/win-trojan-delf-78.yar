rule Win_Trojan_Delf_78
{
strings:
	$a0 = { 40008d45e8ba02000000e8f9f0ffffc3e96bebffffebeb5be8d7efffff000000ffffffff410000000d0a426f6d62612076312e32205b3034204a756e20323030325d0d0a0d0a }


condition:
	$a0
}