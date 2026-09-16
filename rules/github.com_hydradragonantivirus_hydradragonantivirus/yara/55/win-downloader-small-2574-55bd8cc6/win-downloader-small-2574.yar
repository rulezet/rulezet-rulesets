rule Win_Downloader_Small_2574
{
strings:
	$a0 = { f35589e580e5ad81ec9400000081ecfc0c000080cc5489e3b0e08925ff4c4000a13760400080cd6b8983b6090000a13b }


condition:
	$a0
}