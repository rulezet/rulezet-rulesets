rule Win_Trojan_Tomy_1
{
strings:
	$a0 = { 5601b89f808ed8ba0032b440cd213d000075c00e1fb43e8b1e5401cd21b43e8b1e56011ecd21 }


condition:
	$a0
}