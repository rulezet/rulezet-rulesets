rule Win_Trojan_Baboon_1
{
strings:
	$a0 = { 018b168a01e8620088dfb403b009e85900b403b001 }


condition:
	$a0
}