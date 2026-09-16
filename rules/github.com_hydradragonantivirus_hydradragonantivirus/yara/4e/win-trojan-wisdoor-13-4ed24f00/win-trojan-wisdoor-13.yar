rule Win_Trojan_Wisdoor_13
{
strings:
	$a0 = { 232868dee22d9f673760e2e5099877adadde4041e6580d50a5f6442f0fed1021475f7c961cf3289fd7267653cc6bbd3c6cf2f6152f35d4ece4d9f227e53dca95 }


condition:
	$a0
}