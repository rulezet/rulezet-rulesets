rule Win_Trojan_Mybot_7244
{
strings:
	$a0 = { 19c37811e95874175a5e65ca9fc7b6211cbaa38cb924361ed90843dfe5280e3a79f43887f22afc862d67f078dcbc0c627d9a163b2c9d55efbb5feb4398da5fbd2fb4ca0c53a352ac8eeea1b51842 }


condition:
	$a0
}