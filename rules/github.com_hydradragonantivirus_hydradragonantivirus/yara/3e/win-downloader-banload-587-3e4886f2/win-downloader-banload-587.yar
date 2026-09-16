rule Win_Downloader_Banload_587
{
strings:
	$a0 = { 5eb02bd7a03f814b4f9191ddf87f0219c3e4ae85d8cc2fdee42a6ac90c16b09c3d2b6fbd1ed62b40c7639c8fd19c0bf1495ebdab51fd525507200ee5a551d8de81defd4a }


condition:
	$a0
}