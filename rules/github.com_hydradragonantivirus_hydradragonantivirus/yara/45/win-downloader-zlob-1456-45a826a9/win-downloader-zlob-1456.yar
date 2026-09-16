rule Win_Downloader_Zlob_1456
{
strings:
	$a0 = { e6a7b4ca223abe9bb567605de59f4a61696d25a4fb733a866ea3c1d889a8645230e95ae1c2aedba0367a186d213b0bf172a67ff65cb8b54549e5fe7c2b83a94917b6548585aaf962f4f5d406df8eec31b9 }


condition:
	$a0
}