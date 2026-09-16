rule Win_Trojan_BHO_116
{
strings:
	$a0 = { 50535783e7005256510f8420ffffffe5185dfc }

	$a1 = { 7d011066696c653a2f2f }


condition:
	$a0 and $a1
}