rule Win_Trojan_Hupigon_1707
{
strings:
	$a0 = { 70617373776f7264[0-36]757365726e616d65 }

	$a1 = { 2b4d454449554d3a2b4c4f573a }

	$a2 = { 44656c6574656d652e626174 }


condition:
	$a0 and $a1 and $a2
}