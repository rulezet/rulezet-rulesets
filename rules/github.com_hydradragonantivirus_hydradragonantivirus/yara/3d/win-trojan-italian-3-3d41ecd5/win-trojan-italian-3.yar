rule Win_Trojan_Italian_3
{
strings:
	$a0 = { 96e50359cd217210b002e82900b440b978028d960301cd21b801572e8b8ed1032e8b96d3 }


condition:
	$a0
}