rule Win_Trojan_MalteseAmoeba_1
{
strings:
	$a0 = { 7505b866069dcf3d162b750b81f943067505b80316 }


condition:
	$a0
}