rule Win_Trojan_Taris_1
{
strings:
	$a0 = { 558bec83c4f0b8e84e4000e870d6ffff6a0068884f400068904f40006a00e869d7ffff506a00e8b9d7ffff50e8cbd7ffffe882dfffffe8bddfffffe86cfeffffe877d0 }


condition:
	$a0
}