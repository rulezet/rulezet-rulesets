rule Win_Trojan_VB_78
{
strings:
	$a0 = { 6e006400200053006f006600740077006100720065005c0046002d00500052004f005400390035005c002a002e002a }

	$a1 = { 425070ff7f9cd6ff95b8ffff91b3f9ff96bdfcff9fcfffffade9ffffbffdffffd9ffffffbde4e5f8 }


condition:
	$a0 and $a1
}