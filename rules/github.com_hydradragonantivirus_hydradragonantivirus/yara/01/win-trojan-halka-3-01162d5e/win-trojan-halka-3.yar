rule Win_Trojan_Halka_3
{
strings:
	$a0 = { cd2180fe017510b801038aee8acaba80008d9e0001cd13e800008bfc368b2d81ed1c0144441e }


condition:
	$a0
}