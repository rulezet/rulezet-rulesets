rule Win_Trojan_BadSize_1
{
strings:
	$a0 = { 51521e065756e800005e56fc83c688bf0001b90300f3a45eb41a8d94f9008bc42d80003bd07203e9c100b41acd }


condition:
	$a0
}