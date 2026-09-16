rule Win_Trojan_Invol_2
{
strings:
	$a0 = { 88b9ac02908cdd8cc88ed8908ec033f68bfe90fc90ad9033c2ab }


condition:
	$a0
}