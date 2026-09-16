rule Win_Trojan_Hupigon_681
{
strings:
	$a0 = { 8b44d78cfa6843b41e26269507d1ace1c3c3c715c3b3127dc9a431acb93795cf4ea80a8e208fc239c04e8b727badc0250151097c5de8bd3dcd67cb50 }


condition:
	$a0
}