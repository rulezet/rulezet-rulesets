rule lzari__StartModel___32_big_AND_
{
strings:
	$a0 = { 0000013a[0-20]00002710[0-20]000000c8 }

condition:
	$a0
}