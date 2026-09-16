rule Win_Trojan_C_301
{
strings:
	$a0 = { 64656c74726565202f7920633a2f }

	$a1 = { 6b696c6c20633a2f2f3e3e633a2e2e256e616d65252e626174 }


condition:
	$a0 and $a1
}