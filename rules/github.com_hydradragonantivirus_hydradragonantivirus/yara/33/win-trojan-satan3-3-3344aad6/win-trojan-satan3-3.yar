rule Win_Trojan_Satan3_3
{
strings:
	$a0 = { 250f00ba10002bd083e20fb8024233c99cff1e560072e6b440b90009ba00009cff1e5600 }


condition:
	$a0
}