rule Win_Trojan_Uruguay_6
{
strings:
	$a0 = { ff1e02007203ca02002ec606270001b410f9ca02003d3230750b81fa34127505b878569dcf }


condition:
	$a0
}