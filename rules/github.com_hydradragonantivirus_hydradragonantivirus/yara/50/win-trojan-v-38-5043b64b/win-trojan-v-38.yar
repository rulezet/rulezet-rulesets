rule Win_Trojan_V_38
{
strings:
	$a0 = { 4f00ec00052f2b666a6805c824c88505b507bcd507bf0505c8238eda84c64704b107ed24058ef684c3dd0523fb0123 }


condition:
	$a0
}