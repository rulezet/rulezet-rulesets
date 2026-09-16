rule Win_Trojan_HH_3
{
strings:
	$a0 = { b118b440ba0d03e85d005a59b80042e8550033d2b440b900048306fc0201cd21803e0c0300 }


condition:
	$a0
}