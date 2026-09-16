rule Win_Trojan_Agent_33342
{
strings:
	$a0 = { cd68e2500c846ec026c996bd3ed8cd73e5ed0da882828877a7b30f096762a0bafd48b36b078a0bdb75a97e4b53e79469ee0fa86abfe10c615fbf607c4d8d4619f2ebebb8de7647dc3181c27d4e9b }


condition:
	$a0
}