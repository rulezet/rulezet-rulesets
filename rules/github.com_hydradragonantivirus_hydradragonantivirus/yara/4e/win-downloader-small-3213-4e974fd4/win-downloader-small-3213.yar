rule Win_Downloader_Small_3213
{
strings:
	$a0 = { 1619f9a78a5b4185144b08071ac82d1d8a5b0bad4d9ea180703b3cadb342a3ad0d80ed9b169f69fc3a5b993aeaa4a709006baa73435f990ab99ff921923b3c9cc640a622f146 }


condition:
	$a0
}