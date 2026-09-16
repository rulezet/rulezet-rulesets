rule Win_Trojan_VLAD_9
{
strings:
	$a0 = { 49b94c012e813500004747e2f7c35d81ed03001e068dbe2000e8e5ff }


condition:
	$a0
}