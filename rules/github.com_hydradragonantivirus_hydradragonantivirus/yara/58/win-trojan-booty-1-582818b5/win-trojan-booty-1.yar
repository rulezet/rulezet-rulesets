rule Win_Trojan_Booty_1
{
strings:
	$a0 = { e661b000e67050e47188c4e47138e074fa58e661c7070010fe4f02750d52b80404bac403ef5a }


condition:
	$a0
}