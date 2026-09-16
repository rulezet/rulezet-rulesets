rule Win_Trojan_MF_6
{
strings:
	$a0 = { 50001e579afb042400bfcc000e57e843ffbfd2000e57e83bffeb295b4c6974746c654f7665722c }


condition:
	$a0
}