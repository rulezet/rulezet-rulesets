rule Win_Trojan_Small_4124
{
strings:
	$a0 = { bd223c8f03e816000000be9200223cc1 }


condition:
	$a0
}