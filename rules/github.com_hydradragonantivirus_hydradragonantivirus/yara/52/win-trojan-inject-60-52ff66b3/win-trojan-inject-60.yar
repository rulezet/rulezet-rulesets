rule Win_Trojan_Inject_60
{
strings:
	$a0 = { 558bec03750c03c633c98bd433d068de1541 }

	$a1 = { 4000ff2544c04000ff250cc040 }


condition:
	$a0 and $a1
}