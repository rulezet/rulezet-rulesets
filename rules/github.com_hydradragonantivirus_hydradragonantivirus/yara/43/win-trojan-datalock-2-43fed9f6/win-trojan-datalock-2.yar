rule Win_Trojan_Datalock_2
{
strings:
	$a0 = { c3b4becd213d3412c31ea12c00508cd8488ed8812e }


condition:
	$a0
}