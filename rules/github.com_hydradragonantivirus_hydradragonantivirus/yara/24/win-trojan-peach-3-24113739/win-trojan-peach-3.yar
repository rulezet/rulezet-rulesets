rule Win_Trojan_Peach_3
{
strings:
	$a0 = { d2e851ffb440b918008bd7807d015a7406b91300ba }


condition:
	$a0
}