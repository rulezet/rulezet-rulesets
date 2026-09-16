rule Win_Downloader_VB_402
{
strings:
	$a0 = { 01d06656b30c3d5fdb97c256b8efad8bff07a1efe3364b168bfb3fe246dc4c1e3dfde6bdb99c6c7fc71379171f43cb369a01ec62f48faa5d8ca56119eef455ade8 }


condition:
	$a0
}