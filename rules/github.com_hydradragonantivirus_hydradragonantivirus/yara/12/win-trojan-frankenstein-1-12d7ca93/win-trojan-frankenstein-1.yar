rule Win_Trojan_Frankenstein_1
{
strings:
	$a0 = { 4a7c2e8a0e4c7c2e8a364b7c2e8a16497ccd137202eb1e2ec70672043412ea0000ffff }


condition:
	$a0
}