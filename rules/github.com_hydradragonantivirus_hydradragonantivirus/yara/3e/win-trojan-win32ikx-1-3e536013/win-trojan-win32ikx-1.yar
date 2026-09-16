rule Win_Trojan_Win32IKX_1
{
strings:
	$a0 = { e61240006467ff36000064678926000081e600f0ffff6066ad663d4d5a74226181ee00100000eb }


condition:
	$a0
}