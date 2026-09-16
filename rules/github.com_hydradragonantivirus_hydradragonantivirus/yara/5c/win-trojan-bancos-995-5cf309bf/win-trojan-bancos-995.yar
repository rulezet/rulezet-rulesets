rule Win_Trojan_Bancos_995
{
strings:
	$a0 = { b35834ebf038e374a974a0f6b59b4f94a077944db4107453abc44cc78ddcf1c3b2ca6d54bc16d682766e4746b4bdef662410944dbf2bff4bfd852c72c74fdaf783136bf1a759ba82dc96af339121fb00948f }


condition:
	$a0
}