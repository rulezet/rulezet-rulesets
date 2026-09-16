rule Win_Trojan_Merlin_1
{
strings:
	$a0 = { 5d8db6920033ffb9d80d56565351d1e72e8b8381002e8946292e8946642e8b838a002e8946 }


condition:
	$a0
}