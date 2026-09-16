rule Win_Spyware_Banker_2701
{
strings:
	$a0 = { 5c3ba50e67e1714918bc8ea080cb13c2e1d5b54e3eb62ca0e8a19849d164a527fe9a7556dfba83a43e24f1a6581437eeb5a02b693a93a6eecfbb }


condition:
	$a0
}