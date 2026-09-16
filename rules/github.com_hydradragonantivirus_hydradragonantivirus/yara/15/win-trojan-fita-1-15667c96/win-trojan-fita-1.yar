rule Win_Trojan_FITA_1
{
strings:
	$a0 = { 8db68702bf000157a4a5b447b2008db6c202cd213ec686c1025c3ec6869602038d969702e82200b44eb927008d }


condition:
	$a0
}