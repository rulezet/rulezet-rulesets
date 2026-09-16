rule Win_Trojan_Kobr_1
{
strings:
	$a0 = { 16579a3e00bd0089ec5dc3032a2e2a2b6b6f627239392076657273696f6e287465726d696e }


condition:
	$a0
}