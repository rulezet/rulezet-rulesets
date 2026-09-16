rule Win_Trojan_Bancos_1740
{
strings:
	$a0 = { 1a913f307acc9ec94a0ff077d71c9e32ab075149689b7ce0f6c4a12a14feed7586d8a517e669555a6fdf81bbc7d8ff86ba31f5b283daea81f4a97f3a2578842cc28be076120e }


condition:
	$a0
}