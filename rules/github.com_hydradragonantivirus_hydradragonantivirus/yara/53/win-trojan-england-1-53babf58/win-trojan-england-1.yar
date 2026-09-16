rule Win_Trojan_England_1
{
strings:
	$a0 = { b43ee80700e82d00ffe5b43fcd21c34d61646520696e20456e676c616e64 }


condition:
	$a0
}