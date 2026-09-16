rule Win_Trojan_Strike_1
{
strings:
	$a0 = { 1304a11304b106d3e08ec0a35e7cfcb90002f3a4be4c00bff700a5a58944fec744fce5008ed8 }


condition:
	$a0
}