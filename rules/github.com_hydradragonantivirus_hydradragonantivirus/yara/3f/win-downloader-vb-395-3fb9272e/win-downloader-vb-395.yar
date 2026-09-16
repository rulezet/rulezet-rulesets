rule Win_Downloader_VB_395
{
strings:
	$a0 = { 0260a94aa1f1493cfeb05cc48cc3d7e56050292fd5d3bbee80f17d24bf2c5bd93d2772768f814c7d9c472b5e4cc2bf4ce2ce44c1d30d663df4e5303b1f7d03327b }


condition:
	$a0
}