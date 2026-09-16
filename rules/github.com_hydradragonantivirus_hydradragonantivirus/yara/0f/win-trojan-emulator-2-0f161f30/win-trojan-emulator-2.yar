rule Win_Trojan_Emulator_2
{
strings:
	$a0 = { 40b9f9008d960301cd21582d0300c686fc01e98986fd01b8004233c999cd21b440b903008d96fc }


condition:
	$a0
}