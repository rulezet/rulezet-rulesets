rule Win_Trojan_Amber_1
{
strings:
	$a0 = { e800005d83ed03b96400be????bf6aef90fcf3a4be????03f5bf????90b90300fcf3a4b44eb92000ba430103d5cd2173 }


condition:
	$a0
}