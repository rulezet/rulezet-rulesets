rule Win_Trojan_Signed_3
{
strings:
	$a0 = { 03be46008bfe8a1e09008a0432c388054647fec34983 }


condition:
	$a0
}