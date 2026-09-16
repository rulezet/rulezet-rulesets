rule Win_Trojan_Hipp_2
{
strings:
	$a0 = { b918008d964504e87bfeb91d0351eb28902e8b8e330481c10c012e898e0c01b8004231c931d2 }


condition:
	$a0
}