rule Win_Trojan_DVC_1
{
strings:
	$a0 = { 81ed0a01fcbe030103f5bf470203fdb90300f3a67419be030103f5bf0001b90300f3a4b9000151be8000bf00f0f3a4 }


condition:
	$a0
}