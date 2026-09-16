rule Win_Trojan_Fifo_2
{
strings:
	$a0 = { a44bcd21fcb94d01be00015673281e065133c08ec0bf0002f3a40c108ed8fa2687068600a33b02b84b01268706 }


condition:
	$a0
}