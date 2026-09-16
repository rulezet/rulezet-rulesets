rule Win_Trojan_Happy_4
{
strings:
	$a0 = { 3ea60303f8268855ffa1a0013b46fe75ccbf22031e57c43ea6030657ff36ae0331c050509a330c }


condition:
	$a0
}