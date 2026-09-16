rule Win_Downloader_Swizzor_491
{
strings:
	$a0 = { c7fbd2601867a20c1f496c2872e5602ba3ab643d45fe6ce26e43c9071e3ac4a46a0e88109be08233b751dff3fc11b21d143f8d131487d3be84f8e8be909e12ccc9bea363bb64b6c9ea19d2c450db }


condition:
	$a0
}