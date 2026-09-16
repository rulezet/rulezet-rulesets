import "pe"
rule StarForceV1XV3XStarForceCopyProtectionSystem
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}