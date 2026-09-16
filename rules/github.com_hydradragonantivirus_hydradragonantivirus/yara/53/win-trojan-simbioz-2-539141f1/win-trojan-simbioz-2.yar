rule Win_Trojan_Simbioz_2
{
strings:
	$a0 = { 21720cb440b90901900e1f8bd5cd21b43ecd21e967ffb41a2ec516f000cd21071f61552e8b }


condition:
	$a0
}