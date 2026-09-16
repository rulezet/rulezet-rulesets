rule Win_Downloader_117_2
{
strings:
	$a0 = { 8294fcaef0ee84ac7a1d2b46e70194538ad1a0efc85428520f11d4d84aed8b0d54d8170684fd55bf4f18d4535c478360d4a8e3510f11e79382ac15a5f0ee5ccecfe72bacfcba5f26079889ab69ba7ed84a1d }


condition:
	$a0
}