rule Win_Trojan_Small_144
{
strings:
	$a0 = { 03f78b5cfe03df07060e03ff26382d7515b17cf3a4be840026a526a526c744fc3c02268c44fe07ffe3b44233 }


condition:
	$a0
}