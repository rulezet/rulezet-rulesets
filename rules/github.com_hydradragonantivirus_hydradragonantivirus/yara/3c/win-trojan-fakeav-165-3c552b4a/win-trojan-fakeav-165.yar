rule Win_Trojan_FakeAV_165
{
strings:
	$a0 = { 5781ec000200008bfc6a7c57e8????????8d4f7c515703f8b85c6d6369abb871747a33abb8322e646cabb86c000000ab }


condition:
	$a0
}