rule Win_Trojan_V_44
{
strings:
	$a0 = { 0101050300b104d3e88cdb03c30510008ed8be7a01bf0001b90300f3a4b8cdabf8cd217303e93b0133c08ec026a1 }


condition:
	$a0
}