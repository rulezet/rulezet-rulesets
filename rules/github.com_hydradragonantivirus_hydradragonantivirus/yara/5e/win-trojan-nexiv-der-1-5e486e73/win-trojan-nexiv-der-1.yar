rule Win_Trojan_Nexiv_Der_1
{
strings:
	$a0 = { e80100c39c505351525657551e06fbfce80000582d1401b104d3e88ccb03c350b8260150cb0e1f81fce87b7437803e }


condition:
	$a0
}