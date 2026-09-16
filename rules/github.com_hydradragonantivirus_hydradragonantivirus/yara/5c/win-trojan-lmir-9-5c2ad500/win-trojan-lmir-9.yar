rule Win_Trojan_Lmir_9
{
strings:
	$a0 = { 01e7250bb6cbdf0acdff5f6c6567656e64206f6620ffff7f0ba953792d0026fc1b8bda0a9361a16a8452548cadc40333e8ff7fa954a220ea732b0801e4 }


condition:
	$a0
}