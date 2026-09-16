rule Win_Trojan__0259_0001_003_1
{
strings:
	$a0 = { b8004233c999cd21b4408d966f0459cd21fe8e6e04e9f3feb801438d966104cd21c3b4408d }


condition:
	$a0
}