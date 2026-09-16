rule Win_Trojan_Halka_1
{
strings:
	$a0 = { 01008d965801cd21b90200be9a008dbe5a01f3a43e80865a01015b53b440b902008d965a01cd21 }


condition:
	$a0
}