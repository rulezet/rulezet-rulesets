rule Win_Trojan_NetSphere_3
{
strings:
	$a0 = { b4fcdf54d8644bc5d196a34acce675d49aa740ac369f90fea626608ca30323c743ae1f33ad907b6134e51b09464c2339173f97f65c677421 }


condition:
	$a0
}