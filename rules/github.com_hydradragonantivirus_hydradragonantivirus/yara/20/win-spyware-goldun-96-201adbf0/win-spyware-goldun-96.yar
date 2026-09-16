rule Win_Spyware_Goldun_96
{
strings:
	$a0 = { 722e73796d610bf8542c3163d56469718854fc6d741e2e6d63616665e900bb010d1a046164 }


condition:
	$a0
}