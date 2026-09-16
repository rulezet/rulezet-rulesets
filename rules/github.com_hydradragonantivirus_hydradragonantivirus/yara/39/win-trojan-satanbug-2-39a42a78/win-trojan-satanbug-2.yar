rule Win_Trojan_SatanBug_2
{
strings:
	$a0 = { 35a1a602daa3715ea1e2fd265cfd290ed01ef916005d31587475 }


condition:
	$a0
}