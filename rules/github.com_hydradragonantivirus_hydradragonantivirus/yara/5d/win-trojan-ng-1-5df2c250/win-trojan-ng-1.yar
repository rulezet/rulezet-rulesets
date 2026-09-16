rule Win_Trojan_NG_1
{
strings:
	$a0 = { 1e3901cd21c3b440ba0001b90c04ebee53502ea003010c80bb04012e30074381fb360175f6585b }


condition:
	$a0
}