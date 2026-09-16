rule Win_Trojan_Bancos_1798
{
strings:
	$a0 = { 35a4c76dd1c079543ea0c56f59dd586950ae37dd0cea9c8b5b1eaf7172864be08779cc3ff33fa3852a52cf709aeb53ed1b9a1de81e7c94c8da7470b44cfae533c95fd287db16 }


condition:
	$a0
}