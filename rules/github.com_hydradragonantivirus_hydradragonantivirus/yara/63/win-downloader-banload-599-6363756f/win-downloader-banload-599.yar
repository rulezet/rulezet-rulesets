rule Win_Downloader_Banload_599
{
strings:
	$a0 = { f1bfa9eea84fd4bee14958ef003192fd9a4946021147cc0ef9f0f3391742e36b3bbdf86be30e9232bf74288a46301c8c41d4f79fa7b04d131317fd6a6fca4c97c4d346b7 }


condition:
	$a0
}