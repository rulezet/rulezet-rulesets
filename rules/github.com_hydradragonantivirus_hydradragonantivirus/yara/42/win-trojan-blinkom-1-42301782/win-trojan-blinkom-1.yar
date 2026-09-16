rule Win_Trojan_Blinkom_1
{
strings:
	$a0 = { 52615a132f4745445a4143af0c2da5fb3735372031203431340f3cb3f1ffa62f548d434f4c4f4d424941315d }


condition:
	$a0
}