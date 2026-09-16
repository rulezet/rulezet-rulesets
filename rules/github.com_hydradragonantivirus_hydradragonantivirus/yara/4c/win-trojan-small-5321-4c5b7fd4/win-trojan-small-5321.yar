rule Win_Trojan_Small_5321
{
strings:
	$a0 = { 5602d27bd945225a1cb3cd5a680ad39a9aa325bfab67826f567f66c8c08065ceb4dc6832ab0afac0a7d263c6e1fc15f2bb870dfa9dbb103665365675db4897bc52fe4cfc06880e6f560a546be18d }


condition:
	$a0
}