rule Win_Trojan_Plagiarist_2
{
strings:
	$a0 = { c30004832f0389deadb106d3e08ec0b9030051b80402bb00008b0e427c8b16447ccd1359 }


condition:
	$a0
}