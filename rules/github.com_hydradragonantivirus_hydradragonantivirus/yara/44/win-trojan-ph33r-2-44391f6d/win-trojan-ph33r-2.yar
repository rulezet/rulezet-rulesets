rule Win_Trojan_Ph33r_2
{
strings:
	$a0 = { 163106e82000b440b93d0633d2e816008f06ea058f06e805b440b90a00ba3306e80300e959 }


condition:
	$a0
}