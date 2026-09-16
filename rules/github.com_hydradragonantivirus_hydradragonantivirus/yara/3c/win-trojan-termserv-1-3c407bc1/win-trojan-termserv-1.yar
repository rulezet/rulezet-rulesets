rule Win_Trojan_Termserv_1
{
strings:
	$a0 = { 8518ffffff1c054000c7851cffffff08054000c78520fffffffc04400089852cffffffc78530fffffff4044000c78534ffffffe0044000898538ffffff89853cffffff740de896fcffff6a00ff1588024000 }


condition:
	$a0
}