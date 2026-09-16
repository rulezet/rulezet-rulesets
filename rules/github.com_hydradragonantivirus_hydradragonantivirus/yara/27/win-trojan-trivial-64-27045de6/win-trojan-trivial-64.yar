rule Win_Trojan_Trivial_64
{
strings:
	$a0 = { 10008ed8b430cd213c00745ab42fcd21891e82008c068400ba8600b41acd21b44eb90100ba6d00cd21723b8a26 }


condition:
	$a0
}