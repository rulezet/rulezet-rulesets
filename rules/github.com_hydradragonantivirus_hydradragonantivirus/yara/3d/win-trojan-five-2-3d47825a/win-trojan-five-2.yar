rule Win_Trojan_Five_2
{
strings:
	$a0 = { 4602b84dd433dbcd2f3ddd447412b8ffffcd213daaaa74088306570201e87100be3e01fcb93d02bf7b03 }


condition:
	$a0
}