rule Win_Trojan_House_1
{
strings:
	$a0 = { 81ed5942b813408bfe304509fec085e4474d75f5 }


condition:
	$a0
}