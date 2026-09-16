rule Win_Downloader_Delf_35
{
strings:
	$a0 = { 0a56eb7b168744ac8c9bf2c68bb00b1e072356f41a30de935ac0b5461f49165e34de0db31af93f85375c636d7273662e6578652fefffbf0bfe7474703a2f2f636172 }


condition:
	$a0
}