rule Win_Downloader_329_1
{
strings:
	$a0 = { 32fcb5adfa8acba370e6e08dc434dcddd5e2846a7ffd203de9f547a9d3621415521bd769173ae60be1fa31bf8aafd7824bfd7437e4d9b37d1e236c70f4cd21814cf62698300faca6f4e3d6b49db4b1796ea4634b }


condition:
	$a0
}