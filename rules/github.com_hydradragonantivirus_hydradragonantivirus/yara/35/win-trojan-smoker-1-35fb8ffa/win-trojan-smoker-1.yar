rule Win_Trojan_Smoker_1
{
strings:
	$a0 = { ee0350535152571e0656b8a0edcd213dffff74378cc0488ec0bb030026832f29904b8b072d290089078ec033fffc }


condition:
	$a0
}