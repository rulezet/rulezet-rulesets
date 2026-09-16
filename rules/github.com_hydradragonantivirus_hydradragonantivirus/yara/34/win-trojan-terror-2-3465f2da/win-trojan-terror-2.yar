rule Win_Trojan_Terror_2
{
strings:
	$a0 = { 8c1e410550b859eccd213be8753e0e }


condition:
	$a0
}