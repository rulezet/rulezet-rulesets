rule Win_Trojan_Expiro_2
{
strings:
	$a0 = { 60e8002b020061e9 }

	$a1 = { 89e581ec380100005356578d059f }


condition:
	$a0 and $a1
}