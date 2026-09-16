rule Win_Trojan_Zperm_1
{
strings:
	$a0 = { e90000000060bd??????00e81f0000008b642408f964678f06000058e8070000008944241c61ffe068??????0058c3??c064ff30 }


condition:
	$a0
}