rule Win_Trojan_Bifrose_173
{
strings:
	$a0 = { d2dee4290402590bfbb457af40abc55e07e76f099fbdbfe0657dcede1401686448232605ba20d1c50043e9fa9490b09ddff82438624d03fe5b5230f4e04c9a0a0009fd8b }


condition:
	$a0
}