rule Win_Downloader_Agent_31845
{
strings:
	$a0 = { 9298fefd94f73663ec9f281acac6135b0c47a93d9640601c4a3d7238d15938460c3aad35a0139aad3eb683cf2a0406e21c80e0076b5e480bd64853dafaa2fdd8489fc16ef8298cba4a2505 }


condition:
	$a0
}