rule Win_Trojan_AK_4
{
strings:
	$a0 = { b903008bfd81c7????2e8b0435????2e89054646f94747e2f08bc2d7b44eb920008bd581c2????cd2172 }


condition:
	$a0
}