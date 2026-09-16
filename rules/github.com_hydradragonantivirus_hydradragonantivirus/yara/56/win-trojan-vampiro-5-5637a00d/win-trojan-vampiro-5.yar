rule Win_Trojan_Vampiro_5
{
strings:
	$a0 = { 04008d965004cd21b80242b90000ba0000cd213e83868603035bb440b9e8038d960001cd21 }


condition:
	$a0
}