rule Win_Downloader_Delf_984
{
strings:
	$a0 = { 2e2ae50439e22cdd4350bd254c8d61b68dcf6ef6c54e136e157dff4ec9ea4c8ce75088c4089b8b62b715329ed358bc6cf5bc2716f4868e5a22c7f372c8591d2f2b3c3216b1bb }


condition:
	$a0
}