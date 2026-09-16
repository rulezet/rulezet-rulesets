rule Win_Downloader_Banload_596
{
strings:
	$a0 = { 5bf0c51643a03bcc5e1732387c1c4ebc905b88f94bf15da7d6aff89b4374493494cd81f5fd5f05321b310ca90dd90c0c4ccaf1f9f214c72aea0dd30810c2db3aea4362d6 }


condition:
	$a0
}