rule Win_Trojan_Mickey_1
{
strings:
	$a0 = { 038b36080083fe037410b00e83fe0e7409b280c606070004b011bb0050908ec3cd13730432e4 }


condition:
	$a0
}