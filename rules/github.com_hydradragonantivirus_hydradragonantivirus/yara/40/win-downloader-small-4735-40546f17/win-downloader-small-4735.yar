rule Win_Downloader_Small_4735
{
strings:
	$a0 = { bf3c12400083c9ff33c0f2aef7d12bf9508bf78bd18bfd83c9fff2ae8bca4fc1e902f3a58bca6830124000 }


condition:
	$a0
}