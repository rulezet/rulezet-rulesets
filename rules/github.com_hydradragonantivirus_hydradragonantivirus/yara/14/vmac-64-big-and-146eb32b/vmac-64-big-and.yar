rule VMAC__64_big_AND_
{
strings:
	$a0 = { fffffffffffffeff[0-20]3fffffffffffffff[0-20]7fffffffffffffff[0-20]ffffffffffffffff[0-20]1fffffff1fffffff }

condition:
	$a0
}