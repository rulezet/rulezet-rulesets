rule Win_Trojan_Zeus_2
{
strings:
	$a0 = { 8ed0bc007c8ed8b96900be547cb85090e87a00bb540836212656f61459f99320fc105fc3ab1e9d62da1ad66ec8 }


condition:
	$a0
}