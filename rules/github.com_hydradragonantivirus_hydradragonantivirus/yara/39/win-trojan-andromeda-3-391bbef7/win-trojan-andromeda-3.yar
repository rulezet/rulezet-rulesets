rule Win_Trojan_Andromeda_3
{
strings:
	$a0 = { 2acd213c01740e3c03740a3c057406e82403eb0490e81703bedfafb430cd2181ffc3c3751c }


condition:
	$a0
}