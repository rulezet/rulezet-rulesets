rule Win_Trojan_Munya_2
{
strings:
	$a0 = { 130403a11304c1e00633f68ec0b932018a9c557c26881c46e2f6061f56b802028b0e50008b16 }


condition:
	$a0
}