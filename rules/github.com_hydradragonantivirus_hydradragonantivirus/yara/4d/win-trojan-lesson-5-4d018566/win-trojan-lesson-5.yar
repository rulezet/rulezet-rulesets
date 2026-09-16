rule Win_Trojan_Lesson_5
{
strings:
	$a0 = { 565e5e81c62701bf0001fca5a581ee2e01e81500eb2d90e80f00b440b932018bd6cd21e803 }


condition:
	$a0
}