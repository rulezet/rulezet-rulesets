rule Win_Trojan_Peed_184
{
strings:
	$a0 = { b924dade0133dd85c5e8030000002b8bc9558bec45f7d968d62726 }


condition:
	$a0
}