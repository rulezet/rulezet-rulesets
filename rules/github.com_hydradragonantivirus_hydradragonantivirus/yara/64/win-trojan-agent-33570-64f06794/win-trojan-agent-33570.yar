rule Win_Trojan_Agent_33570
{
strings:
	$a0 = { b86d1fdaeadd7e71f5fedab733ac0d91ac392e30354a9556fa612fd138300745b4f1ebb9f84ab83fa19b89d7561bbf2a14a3d570a373deaf7768ed735c70d70c6037bfe47ba77684b2e8e4f0c0695d250ad9 }


condition:
	$a0
}