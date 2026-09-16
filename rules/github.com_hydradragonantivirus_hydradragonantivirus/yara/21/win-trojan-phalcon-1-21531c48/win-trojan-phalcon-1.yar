rule Win_Trojan_Phalcon_1
{
strings:
	$a0 = { 0299b90001cd26e90000fab003b9bc02ba00008e5d638b }


condition:
	$a0
}