rule Win_Trojan_XEP_1
{
strings:
	$a0 = { 031eeb0283c310532eff36e902fc50061e33ff8ec7268b3e720057268b3e7000070e1fbee400b91400f3a67503 }


condition:
	$a0
}