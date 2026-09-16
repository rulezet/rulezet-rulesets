rule Win_Downloader_668_1
{
strings:
	$a0 = { 616ab1da364578bd9aa86b36fd2b61ea6874c4703a712f6f7702ef63e775624de7bc86fce9ec2f66dd845d6d866a7363b03b70747ff1 }


condition:
	$a0
}