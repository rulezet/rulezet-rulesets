import "pe"
rule CryptKeyV56XDLLKenonicControlsLtd
{
	meta:
		author="malware-lu"
strings:
		$a0 = { 8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 ?? ?? ?? ?? E8 }

condition:
		$a0 at pe.entry_point
}