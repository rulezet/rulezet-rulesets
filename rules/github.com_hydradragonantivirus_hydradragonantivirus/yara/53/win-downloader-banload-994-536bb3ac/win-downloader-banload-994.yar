rule Win_Downloader_Banload_994
{
strings:
	$a0 = { 38fed15fa61505d35d1bf1743ddf0c724104d9a38fe8870348d30b6c6fd019725bf8c1bd1d1c1ec7508b98c46c82a77ef52d216ef4984aac08b165006c8bb86f46372f5fc7ffd633a8069bc5d65b }


condition:
	$a0
}