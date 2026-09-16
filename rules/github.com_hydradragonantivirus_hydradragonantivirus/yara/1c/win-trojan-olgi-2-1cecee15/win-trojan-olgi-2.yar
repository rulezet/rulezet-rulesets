rule Win_Trojan_Olgi_2
{
strings:
	$a0 = { 8c86c5000e0e1f078db6bd008dbeb500b90400fcf3a5b8124bcd213d34127506909090eb62908b86c500488ed8 }


condition:
	$a0
}