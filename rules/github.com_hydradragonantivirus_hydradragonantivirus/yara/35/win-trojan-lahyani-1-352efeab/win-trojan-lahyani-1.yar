rule Win_Trojan_Lahyani_1
{
strings:
	$a0 = { 7be86a04cd2180fa0e752bb405b00acd10b4098d967b05cd21b30053b003b90a00ba0100cd26 }


condition:
	$a0
}