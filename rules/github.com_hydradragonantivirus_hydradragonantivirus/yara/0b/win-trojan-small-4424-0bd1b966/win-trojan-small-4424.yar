rule Win_Trojan_Small_4424
{
strings:
	$a0 = { 89c58dac28??30420089e8057c38000089c355b8 }


condition:
	$a0
}