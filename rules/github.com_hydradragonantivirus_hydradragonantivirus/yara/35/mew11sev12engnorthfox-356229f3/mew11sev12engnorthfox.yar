import "pe"
rule Mew11SEv12EngNorthfox
	{
	strings:
			$a0 = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C }

	condition:
			$a0 at (pe.entry_point)
	}