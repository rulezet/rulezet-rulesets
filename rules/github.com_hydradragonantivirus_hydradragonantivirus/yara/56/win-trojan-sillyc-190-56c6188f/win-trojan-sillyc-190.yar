rule Win_Trojan_SillyC_190
{
strings:
	$a0 = { e93e8896ea028d960601b97701b440cd21b8004233d233c9cd21b903008d96ea02b440cd213efe }


condition:
	$a0
}