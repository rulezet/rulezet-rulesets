rule Win_Spyware_Banker_5459
{
strings:
	$a0 = { c54bda7661038f73faf9ae96ee904b4aef88ebb19ca18dbfdf01326cc3cf5f381392cdb714cfec75cc77f28d5e618961f5ab3e4c56eee1ebc8c52f5e42eebd3421cbcc13bf5a68396a0a90f3efa7 }


condition:
	$a0
}