rule Win_Trojan_VGEN_232
{
strings:
	$a0 = { be73018104232f46464f75f7c5d1dd2d5ebef2d16a87a0d29cd1de278275a3578dd3de84f75d7356df9dfe5d73 }


condition:
	$a0
}