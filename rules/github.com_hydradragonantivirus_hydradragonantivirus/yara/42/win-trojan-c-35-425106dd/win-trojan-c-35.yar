rule Win_Trojan_C_35
{
strings:
	$a0 = { b409ba3202cd215533ed32e4cd163c0d740d45888679028ad0b402cd21ebeb8bcd5db409ba5502cd21be5802bf7a02 }


condition:
	$a0
}