rule Win_Trojan_Mithrandir_3
{
strings:
	$a0 = { b82135cd21891ee8028c06ea020e5efdacfc561f803e00005a7532a103002d6200722a }


condition:
	$a0
}