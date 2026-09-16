rule Win_Trojan_Gen_168
{
strings:
	$a0 = { 3833ff36346eb8010050ff76fcb8122050e8970d83c408ff36346ee8fa09598d46d050b8ff }


condition:
	$a0
}