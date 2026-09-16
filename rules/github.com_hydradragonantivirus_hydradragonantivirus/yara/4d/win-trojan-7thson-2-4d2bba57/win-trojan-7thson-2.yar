rule Win_Trojan_7thSon_2
{
strings:
	$a0 = { cd21b82435cd215306ba130203d5b82425cd218d965002 }


condition:
	$a0
}