rule Win_Trojan_Kia_3
{
strings:
	$a0 = { 9c06505351525657bf????0e588985????2ec7060001????2ec606020100eb[1-10]1eb8????8ed833d2b41acd211e071fb44eb92000ba2a0203d7cd21 }


condition:
	$a0
}