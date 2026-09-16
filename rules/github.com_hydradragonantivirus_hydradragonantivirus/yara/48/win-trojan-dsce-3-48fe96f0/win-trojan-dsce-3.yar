rule Win_Trojan_DSCE_3
{
strings:
	$a0 = { e3f4e4e287d196899787ffa9f7f64fa7a7ff8ab6a716a3744f2b6ea466f71f84a7f76cfef4a1f0f1f22b67a1a9a01833 }


condition:
	$a0
}