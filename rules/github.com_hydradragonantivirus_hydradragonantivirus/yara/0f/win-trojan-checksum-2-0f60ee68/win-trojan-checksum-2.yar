rule Win_Trojan_CheckSum_2
{
strings:
	$a0 = { 0650535152fab90100e874018bec8b6efefb83c5bd2ef7460401007403e909018cc83e894602ba0001b90500e85101 }


condition:
	$a0
}