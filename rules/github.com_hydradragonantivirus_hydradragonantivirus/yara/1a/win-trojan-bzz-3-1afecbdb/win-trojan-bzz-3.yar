rule Win_Trojan_Bzz_3
{
strings:
	$a0 = { 8b2c81ed03015ecd151adb2e80be4501b8742cb9ea008db63801ff0c812c38d2802ccdf614f71480046ffe04ff }


condition:
	$a0
}