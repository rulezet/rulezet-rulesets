rule Win_Trojan_Astra_3
{
strings:
	$a0 = { d8a184002ea3cd01a186002ea3cf01b805ff9c2eff1ecd013dff05741efc33f68ec60e1fbf }


condition:
	$a0
}