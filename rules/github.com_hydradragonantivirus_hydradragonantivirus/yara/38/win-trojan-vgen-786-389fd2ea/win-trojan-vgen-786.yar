rule Win_Trojan_VGEN_786
{
strings:
	$a0 = { b430cd218b6efafc8d76f93c037c4d560633db8b57028edbb44a4bcd2180ee0533c0cd1291e361b426803ef104 }


condition:
	$a0
}