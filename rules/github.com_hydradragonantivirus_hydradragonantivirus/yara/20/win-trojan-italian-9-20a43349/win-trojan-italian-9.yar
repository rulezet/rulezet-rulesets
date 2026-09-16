rule Win_Trojan_Italian_9
{
strings:
	$a0 = { b944038db614018bfeac2e32a66b04aae2f7c3 }


condition:
	$a0
}