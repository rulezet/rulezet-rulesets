rule Win_Trojan_Nikolas_1
{
strings:
	$a0 = { 42cd217303e92401b440ba2104b90900cd217303e91501b8024233c98bd1cd217303e907010e }


condition:
	$a0
}