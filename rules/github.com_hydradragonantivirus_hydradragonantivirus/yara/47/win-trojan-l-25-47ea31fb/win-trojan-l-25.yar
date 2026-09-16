rule Win_Trojan_L_25
{
strings:
	$a0 = { 018b161701b935012e311483c602e80300e2f5c3c3b419cd2150b40eb202cd21b44732d28db6c503cd21badf01b4 }


condition:
	$a0
}