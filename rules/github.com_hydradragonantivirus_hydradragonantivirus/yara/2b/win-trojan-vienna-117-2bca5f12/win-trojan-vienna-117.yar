rule Win_Trojan_Vienna_117
{
strings:
	$a0 = { 9083c60a9090bf000190b90300f3a4908bf2b430cd }


condition:
	$a0
}