rule Win_Downloader_Delf_1164
{
strings:
	$a0 = { c01ad3e375dc75c0b74ffa6f90f926889f3a10e9b2cea0bd509b4f8ee4bac373227596ea4df0a4b94f981c2d77fd45dd760a37be9d4c4aa0a46ea534bd1942afd084fbed2ee468dddef4fc81ec054103fa }


condition:
	$a0
}