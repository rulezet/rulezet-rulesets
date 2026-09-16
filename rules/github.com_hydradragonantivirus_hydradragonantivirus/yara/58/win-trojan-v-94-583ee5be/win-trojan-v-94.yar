rule Win_Trojan_V_94
{
strings:
	$a0 = { 02cd212ea020032e8a262103482ea32003b41aba6402cd21b427baff02b90100cd212ec7 }


condition:
	$a0
}