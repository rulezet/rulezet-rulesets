import "pe"
rule StarForce30StarForceTechnology
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 63 }

	condition:
			$a0 at (pe.entry_point)
	}