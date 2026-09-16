rule Win_Trojan_Zyflex_1
{
strings:
	$a0 = { be009a000052005589e581ec00019ac2015200bf2e031e579ab007be009a0e02be00bf2e031e579ab007be009a }


condition:
	$a0
}