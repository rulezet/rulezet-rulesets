rule Win_Trojan_Agent_35858
{
strings:
	$a0 = { 33c949ff1508304000ba0000010092e81d0000008b4c240c8b91b00000004a75 }


condition:
	$a0
}