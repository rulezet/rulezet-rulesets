rule RansomFilecoderA
{
	meta:
		Description  = "Ransom.FileCoder.A.vb"
		ThreatLevel  = "5"

	strings:
		$ = "Guji36" ascii wide
		$ = "Burnamedoxi" ascii wide
		$ = "S48H1G54JSPSODKMGdfH1FD5G8DSDPSDKMFSSJJPGMCNDHS2FH5" ascii wide
	condition:
		any of them
}