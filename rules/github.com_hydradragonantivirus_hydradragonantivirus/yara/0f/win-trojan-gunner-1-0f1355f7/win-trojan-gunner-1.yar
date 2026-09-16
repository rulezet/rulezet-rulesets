rule Win_Trojan_Gunner_1
{
strings:
	$a0 = { 9616038dbe5003b456cd218d9626038dbe5c03b456cd218d9635038dbe6803b456cd21c3b42acd }


condition:
	$a0
}