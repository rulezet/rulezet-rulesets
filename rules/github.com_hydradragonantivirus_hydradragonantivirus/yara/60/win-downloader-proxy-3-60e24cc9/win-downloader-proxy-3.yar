rule Win_Downloader_Proxy_3
{
strings:
	$a0 = { 74143dfa700ae5831120676f74975fbc0f69664765785773cf742cd0244330cf2aa7456ebfa36c6564d0636d73e3d39e }


condition:
	$a0
}