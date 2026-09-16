rule Win_Trojan_Positron_1
{
strings:
	$a0 = { 06feff9c601e06b40bbb9419cd21e800005e81ee1300 }


condition:
	$a0
}