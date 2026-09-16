rule Win_Downloader_Agent_31869
{
strings:
	$a0 = { e86388000083c4103bc30f85850000008d4dece808f8ffff68a8c340008d4dece8cbfcffff }


condition:
	$a0
}