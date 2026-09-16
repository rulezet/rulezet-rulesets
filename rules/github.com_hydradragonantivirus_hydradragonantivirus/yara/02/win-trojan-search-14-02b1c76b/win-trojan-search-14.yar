rule Win_Trojan_Search_14
{
strings:
	$a0 = { c02ea2ee028ec0be9000268b042ea3ef0226c704de0226 }


condition:
	$a0
}