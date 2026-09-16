rule Win_Trojan_Infek_1
{
strings:
	$a0 = { 70005589e531c09acd027000c606031601bff8050e57bfee151e57b81400509a8d097000bffe050e57e8e4fcbf }


condition:
	$a0
}