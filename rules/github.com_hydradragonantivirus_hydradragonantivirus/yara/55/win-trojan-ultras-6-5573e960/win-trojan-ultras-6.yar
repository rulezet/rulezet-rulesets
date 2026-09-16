rule Win_Trojan_Ultras_6
{
strings:
	$a0 = { 64656c666972652e736372 }

	$a1 = { 2e72756e2822756c747261732e6261742229 }


condition:
	$a0 and $a1
}