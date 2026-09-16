rule Win_Trojan_Agent_34157
{
strings:
	$a0 = { 68986b400033c964ff3164892133c06a105950e2fd6a448bcc83ec108bd4525150 }


condition:
	$a0
}