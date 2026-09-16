rule Win_Trojan_Pulce_1
{
strings:
	$a0 = { b0847e84650fb7f57a960d10b00eafb703f77a963ca115b03cb93eb00fb7f57a968477396f16dbb3 }


condition:
	$a0
}