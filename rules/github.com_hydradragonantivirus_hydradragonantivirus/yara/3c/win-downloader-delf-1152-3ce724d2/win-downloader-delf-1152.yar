rule Win_Downloader_Delf_1152
{
strings:
	$a0 = { 4993f26fdaa6f459fd0504727999caf957a60c1088077a2b2a53e63ba4c57130f51fef6280d69ab8d9ed975a4b76c360a523229fa04802eb54b81a3c8fbd30bb7ebe0d3eda5304a101bbb1b6a9fcd266d3 }


condition:
	$a0
}