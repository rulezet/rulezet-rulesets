rule Win_Trojan_NARK_1
{
strings:
	$a0 = { 7cfb832e1304028b1e1304b106d3e38ec3b804022bdbb90127cd1352b404cd1a81fa0906740a }


condition:
	$a0
}