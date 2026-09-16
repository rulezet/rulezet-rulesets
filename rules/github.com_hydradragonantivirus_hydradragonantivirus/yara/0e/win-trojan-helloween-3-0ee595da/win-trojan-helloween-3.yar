rule Win_Trojan_Helloween_3
{
strings:
	$a0 = { b827eccd213d524a743f803c00750583fcf072498c }


condition:
	$a0
}