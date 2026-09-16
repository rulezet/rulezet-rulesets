rule Win_Trojan_Stardot_2
{
strings:
	$a0 = { 2683c402595833d2fec83c0075e31f0758fa2e8e162d04 }


condition:
	$a0
}