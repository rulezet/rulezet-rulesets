rule Win_Trojan_BW_3
{
strings:
	$a0 = { 81ed09001e06fab872a950584c4c5b3bc37401f4fbe4213402e6213402e621b872a9217281fa8c1f74348cc0488ed8 }


condition:
	$a0
}