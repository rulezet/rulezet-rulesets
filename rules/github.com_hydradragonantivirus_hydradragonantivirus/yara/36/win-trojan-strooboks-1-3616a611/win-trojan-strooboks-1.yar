rule Win_Trojan_Strooboks_1
{
strings:
	$a0 = { 2acd212e89161501b80042b90000ba5a05cd21b440ba1501b90200cd21b43ecd21b443bab703b0 }


condition:
	$a0
}