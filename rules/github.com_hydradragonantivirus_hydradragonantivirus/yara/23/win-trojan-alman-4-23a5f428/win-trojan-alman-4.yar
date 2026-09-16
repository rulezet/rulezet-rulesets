rule Win_Trojan_Alman_4
{
strings:
	$a0 = { 33c085c0740fcc5bb9cd040000??????????faeb06 }


condition:
	$a0
}