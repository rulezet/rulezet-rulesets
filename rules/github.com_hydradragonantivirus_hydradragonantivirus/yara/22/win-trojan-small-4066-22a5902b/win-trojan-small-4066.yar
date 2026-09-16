rule Win_Trojan_Small_4066
{
strings:
	$a0 = { e835000000f8e87800000029ed81c5008cfffff7dd01dd89ef81c70fdeddf581ef7adbddf581c747050000c3 }


condition:
	$a0
}