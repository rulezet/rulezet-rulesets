rule Win_Trojan_Bob_7
{
strings:
	$a0 = { 9a000073019a000011015589e5b8000c9a7c02730181ec000cbfb4581e57bfb8581e57bfb6581e57bfba581e579a0000 }


condition:
	$a0
}