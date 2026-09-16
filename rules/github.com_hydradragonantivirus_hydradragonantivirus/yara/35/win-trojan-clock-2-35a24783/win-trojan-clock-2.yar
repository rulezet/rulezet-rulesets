rule Win_Trojan_Clock_2
{
strings:
	$a0 = { e2fac356e8d7ffb97e03905a81c2a8ffb440cd21e8c7ff }


condition:
	$a0
}