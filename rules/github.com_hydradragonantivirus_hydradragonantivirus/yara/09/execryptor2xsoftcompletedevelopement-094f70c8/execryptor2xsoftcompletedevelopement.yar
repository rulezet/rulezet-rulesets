rule EXECryptor2xSoftCompleteDevelopement
	{
	strings:
			$a0 = { A4 ?? ?? 00 00 00 00 00 FF FF FF FF 3C ?? ?? 00 94 ?? ?? 00 D8 ?? ?? 00 00 00 00 00 FF FF FF FF }

	condition:
			$a0
	}