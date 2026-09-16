rule Win_Trojan_PPZ_5
{
strings:
	$a0 = { b800330cf8880e49155d0520b2ccb801150f020fa294d4560aea302843702021730433c9eb02 }


condition:
	$a0
}