rule Win_Trojan_Kuarahy_2
{
strings:
	$a0 = { 8b12b440b92200ba7112cd21b92800be7512e8b903a39d1289169f12b440b91000ba9312cd21 }


condition:
	$a0
}