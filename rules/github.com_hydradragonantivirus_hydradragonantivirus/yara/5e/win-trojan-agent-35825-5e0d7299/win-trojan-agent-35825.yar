rule Win_Trojan_Agent_35825
{
strings:
	$a0 = { 6f6e653d6d6964287461626c652c6a2c3129 }

	$a1 = { 6d6964286b65792c6a2c3129 }


condition:
	$a0 and $a1
}