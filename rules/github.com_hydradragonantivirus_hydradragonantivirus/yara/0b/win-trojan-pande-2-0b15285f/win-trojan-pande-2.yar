rule Win_Trojan_Pande_2
{
strings:
	$a0 = { 060000cd20e8bd05558b6e1490e83c008bdd5d8b4602900510002e01472a902e01472090e8ae05bcf0ff8ed4bcfeff }


condition:
	$a0
}