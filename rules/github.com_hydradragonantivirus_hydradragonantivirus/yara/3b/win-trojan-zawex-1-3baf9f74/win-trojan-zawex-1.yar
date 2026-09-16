rule Win_Trojan_Zawex_1
{
strings:
	$a0 = { 33d2e84a0c0000bc82d7248265dca9be90e3c9e4f4e4e40f166f3ce7bcd88265dfb4a191096d614ff6a4e4 }


condition:
	$a0
}