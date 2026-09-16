rule Win_Trojan_Bancos_1108
{
strings:
	$a0 = { d9f7dbe8e06cb1a3d03215665e3a5e0e2e4b2d3d62d3cc5ba9d8c987500e24a07dd2dcfe7220df600036d4b618f647df44a183421caa0cb896045e96d5050d874bd8ed6ab8c92cad662eb2cf9160 }


condition:
	$a0
}