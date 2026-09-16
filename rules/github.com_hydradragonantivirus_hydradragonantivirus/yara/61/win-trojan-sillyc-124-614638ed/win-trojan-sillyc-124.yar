rule Win_Trojan_SillyC_124
{
strings:
	$a0 = { 4233c999cd217210508bd581c20001b440b9ea00cd21730558eb30ebb08bfd81c7e701c605e9 }


condition:
	$a0
}