rule Win_Downloader_182_1
{
strings:
	$a0 = { f0c6859cfcffff65c6858efcffff65c6858dfcffff7480cde4c68595fcffff6480c6a380ce28c68593fcffff6b80e154c68592fcffff6380c12080c5b05580ca7383ec088b858df9ffff89042480e23b8dbd8bfcff }


condition:
	$a0
}