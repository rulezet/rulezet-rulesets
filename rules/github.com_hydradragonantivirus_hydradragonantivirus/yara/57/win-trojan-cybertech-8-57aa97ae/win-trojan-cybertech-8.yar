rule Win_Trojan_CyberTech_8
{
strings:
	$a0 = { 960400b9e10090cd21b80042e8d9ffb4408d96d800b90400cd21e80e00b41aba8000cd2158 }


condition:
	$a0
}