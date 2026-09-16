rule Win_Trojan_Bancos_1799
{
strings:
	$a0 = { 52d30ebec529af37f4ea1c1149240497674d46469ab79852ee20d6e6ca9fcae6ca652553bdcddae5d25fb43eccaa9ae676c0fb5fbb95832e7010422143b7d4daef898483d45c }


condition:
	$a0
}