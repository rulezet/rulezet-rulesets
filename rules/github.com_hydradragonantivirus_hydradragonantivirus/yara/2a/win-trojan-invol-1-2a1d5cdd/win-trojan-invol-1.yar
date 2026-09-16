rule Win_Trojan_Invol_1
{
strings:
	$a0 = { b991028cdd908cc88ed8908ec09033f68bfefc90ad909033c2ab }


condition:
	$a0
}