rule Win_Downloader_Small_3390
{
strings:
	$a0 = { a0e70c3e6f7cfd9f5a4b9d1fdc7ac995d77732848dae58eb275a6459307b7e8f5598c319fa31f9c727a45566a66ce7625fdb55d4cc81b6c7ef8681f98d3aa9c242dda7ec09 }


condition:
	$a0
}