rule Win_Downloader_Small_1249
{
strings:
	$a0 = { 4e902e7379e59c4a745f70dc2f5b7702f86a696e1d7975611e623d0d636f6d08f42f6466691c792a7c673965783820f0af }


condition:
	$a0
}