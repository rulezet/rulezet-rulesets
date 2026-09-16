rule Win_Trojan_Ricketty_1
{
strings:
	$a0 = { 2ec6060d017fb440ba0001b91200cd212e8f060d01b442b90000ba0400b000cd212e8106fa00 }


condition:
	$a0
}