rule Win_Trojan_Romeo_1
{
strings:
	$a0 = { 8ed88c066e03fa8ed0bc308afbb430cd21a370030650b434cd218c061e048bc3485b86df81fb0a037321b9ffff }


condition:
	$a0
}