rule Win_Trojan__0251_0002_000_1
{
strings:
	$a0 = { b8004233c999cd21b4408d967b0359cd21fe8e7a03e91bffb801438d966d03cd21c35bb440 }


condition:
	$a0
}