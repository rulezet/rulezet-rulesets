rule Win_Trojan_SillyCR_1
{
strings:
	$a0 = { cd21bf8d0003fd2e895d012e8c4503520733ff8bf5fcb9fd00f3a4061fba7b00b82125cd21 }


condition:
	$a0
}