rule _PEStubOEP_v1x_
{
	meta:
		description = "PEStubOEP v1.x"
	strings:
		$0 = {40 48 BE 00 ?? ?? 00 40 48 60 33 C0 B8 ?? ?? ?? 00 FF E0 C3 C3}
	condition:
		$0
}