rule Win_Trojan_Peed_119
{
strings:
	$a0 = { 400087d?6a016a026a006a006a056a068d54240052ff138d64241869c0d3 }


condition:
	$a0
}