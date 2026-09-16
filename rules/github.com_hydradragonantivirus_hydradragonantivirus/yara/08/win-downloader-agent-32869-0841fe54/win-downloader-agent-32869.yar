rule Win_Downloader_Agent_32869
{
strings:
	$a0 = { 14828305966c7aeae10b4928a39df5200c295e70d39703e498cd8c10088dd13fbe9d0408b59d6c22f69fc324e34fab02b2ea4e0aaca63a7096507a85f0d9 }


condition:
	$a0
}