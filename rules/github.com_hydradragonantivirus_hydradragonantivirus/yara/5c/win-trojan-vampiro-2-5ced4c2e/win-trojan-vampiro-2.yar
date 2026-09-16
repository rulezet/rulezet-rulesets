rule Win_Trojan_Vampiro_2
{
strings:
	$a0 = { 40b904008d965304cd21b80242b90000ba0000cd213e83868903035bb440b9e8038d960001cd21 }


condition:
	$a0
}