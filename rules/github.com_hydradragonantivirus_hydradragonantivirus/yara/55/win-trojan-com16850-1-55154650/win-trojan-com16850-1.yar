rule Win_Trojan_COM16850_1
{
strings:
	$a0 = { 8b07a3dc42b8008050b8010050ff36dc42e8b10783 }


condition:
	$a0
}