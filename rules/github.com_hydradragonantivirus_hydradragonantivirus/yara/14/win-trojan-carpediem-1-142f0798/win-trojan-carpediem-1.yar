rule Win_Trojan_CarpeDiem_1
{
strings:
	$a0 = { 9618018db64801b9c700311483c602e2f9c3 }


condition:
	$a0
}