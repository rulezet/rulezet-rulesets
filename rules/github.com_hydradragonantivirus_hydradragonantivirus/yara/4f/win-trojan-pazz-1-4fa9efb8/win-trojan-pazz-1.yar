rule Win_Trojan_Pazz_1
{
strings:
	$a0 = { 5283ea03b440b93001cd21b80242b90000ba0000cd212d33018bcb5b5383c30e88074388278bd9 }


condition:
	$a0
}