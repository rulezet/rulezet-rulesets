rule Win_Downloader_Banload_1126
{
strings:
	$a0 = { 9ef4008478d667dda7991a61f17222ddbb732292f091c92aecd4edfe6c59d8d36d36ed41c0dae285da75575e77c6d5cfaf8f67d452f6067afc3edb22 }


condition:
	$a0
}