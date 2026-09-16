rule ARIA_encryption_KRK__32_big_48_
{
strings:
	$a0 = { 517cc1b727220a94fe13abe8fa9a6ee06db14acc9e21c820ff28b1d5ef5de2b0db92371d2126e9700324977504e8c90e }

condition:
	$a0
}