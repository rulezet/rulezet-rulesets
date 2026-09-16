rule Win_Trojan_Evil_Empire_4_1
{
strings:
	$a0 = { c88ec08ed8b99a01bf0500fc8a050405aae2f9e9 }


condition:
	$a0
}