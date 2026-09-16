rule Win_Trojan_F_24
{
strings:
	$a0 = { 4401be28008bfe1e060e1f0e07ada3ad023116ad02a1ad02abeb0590b44ccd21e2eb071f }


condition:
	$a0
}