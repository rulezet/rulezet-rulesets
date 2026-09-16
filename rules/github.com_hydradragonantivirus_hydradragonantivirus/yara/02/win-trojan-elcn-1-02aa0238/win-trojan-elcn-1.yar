rule Win_Trojan_ELCN_1
{
strings:
	$a0 = { 8000bf00fbb90001fcf3a4a14f02050001a3b000b200bec000b447cd21c606b20000be46028bd6c6042ab92700b44e }


condition:
	$a0
}