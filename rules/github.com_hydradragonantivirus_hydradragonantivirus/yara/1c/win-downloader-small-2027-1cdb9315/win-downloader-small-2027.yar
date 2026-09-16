rule Win_Downloader_Small_2027
{
strings:
	$a0 = { 6874e270383a2fbf6787756e6469602e636f6dfa66db6170c6fcf5e3b8796f753d745f7cfe67db581ce76fcc2e8a }


condition:
	$a0
}