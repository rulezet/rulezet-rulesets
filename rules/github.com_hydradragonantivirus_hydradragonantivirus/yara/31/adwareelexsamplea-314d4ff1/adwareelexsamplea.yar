rule AdwareELEXSampleA
{
	meta:
		Description  = "Adware.ELEX.A.vb"
		ThreatLevel  = "5"

	strings:

		$ = "www.freeappstools.com" ascii wide
		$ = "dl.elex.soft365.com" ascii wide
		$ = "E:\\Code\\FileSyn\\Bin" ascii wide
		$ = "E:\\Code_SVN\\FileSyn\\Bin" ascii wide

	condition:
		any of them
}