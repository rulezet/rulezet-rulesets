rule Win_Trojan_CERE1482_1
{
strings:
	$a0 = { 1a4000ff35ce174000ff15a81140000bc00f845affffffbb851a400066813b4d5a0f854affff }


condition:
	$a0
}