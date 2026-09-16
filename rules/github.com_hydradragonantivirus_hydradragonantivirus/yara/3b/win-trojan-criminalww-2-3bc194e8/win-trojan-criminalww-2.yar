rule Win_Trojan_CriminalWW_2
{
strings:
	$a0 = { 0207b104d3ee8cc003c6408ec058c3b80103ba8000b90100cd13b80300cd100e1fbe0f05c7060d }


condition:
	$a0
}