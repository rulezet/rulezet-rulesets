rule Win_Trojan_Gen_188
{
strings:
	$a0 = { fc009a00009a005589e581ec0001e835f931c0a34603c606400300bfa6070e57bf3e001e57b8ff00509a7702fc }


condition:
	$a0
}