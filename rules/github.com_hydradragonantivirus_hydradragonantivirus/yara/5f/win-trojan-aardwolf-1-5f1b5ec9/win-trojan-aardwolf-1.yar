rule Win_Trojan_Aardwolf_1
{
strings:
	$a0 = { 03b8f1f1cd213df2f2750e81c6bc01bf0001a5a5b8000150c38c9cae018c9cb2018c9cb6018cc00510008ec006 }


condition:
	$a0
}