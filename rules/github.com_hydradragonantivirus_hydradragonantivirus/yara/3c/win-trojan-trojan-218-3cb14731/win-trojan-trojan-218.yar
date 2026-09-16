rule Win_Trojan_Trojan_218
{
strings:
	$a0 = { e90000bd6402bb1501cc2e810700004343cc4d75f5 }


condition:
	$a0
}