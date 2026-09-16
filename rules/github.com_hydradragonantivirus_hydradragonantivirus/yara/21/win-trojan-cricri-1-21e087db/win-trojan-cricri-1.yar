rule Win_Trojan_CriCri_1
{
strings:
	$a0 = { 7c8be6fb832e13040990a11304b106d3e08ec033c0cd13b9014fb601b8090233dbcd13720306 }


condition:
	$a0
}