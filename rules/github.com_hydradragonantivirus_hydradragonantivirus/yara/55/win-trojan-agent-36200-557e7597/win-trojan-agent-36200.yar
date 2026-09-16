rule Win_Trojan_Agent_36200
{
strings:
	$a0 = { 56426f78536572766963652e657865 }

	$a1 = { 73696f6e5c52756e }

	$a2 = { 5c7369676e6f6e73332e747874 }

	$a3 = { 6f70656e }


condition:
	$a0 and $a1 and $a2 and $a3
}