rule Win_Trojan_LungHua_1
{
strings:
	$a0 = { be007c1f0e33ff83ac13880456cd12b90001c1e0068ec0f3a58bdfba8000b80602b90900cd13 }


condition:
	$a0
}