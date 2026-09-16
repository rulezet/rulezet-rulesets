rule Win_Trojan_SVS_1
{
strings:
	$a0 = { 3b062303742de85d00c606bf000080fa807419b403bb0002b103b601803e1502fd7402b10e }


condition:
	$a0
}