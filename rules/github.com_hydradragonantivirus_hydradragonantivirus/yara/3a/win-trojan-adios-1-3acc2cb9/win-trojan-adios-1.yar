rule Win_Trojan_Adios_1
{
strings:
	$a0 = { b42acd2181fa080a755cb4098d96????cd21b8023d8d96????cd218bd8b8004233c98bd1cd21b440b903008d96????cd21b8024233c98bd1cd21 }


condition:
	$a0
}