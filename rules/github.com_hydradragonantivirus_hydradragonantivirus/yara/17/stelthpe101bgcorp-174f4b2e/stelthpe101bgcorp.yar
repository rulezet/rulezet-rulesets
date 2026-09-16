import "pe"
rule StelthPE101BGCorp
	{
	strings:
			$a0 = { BA ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}