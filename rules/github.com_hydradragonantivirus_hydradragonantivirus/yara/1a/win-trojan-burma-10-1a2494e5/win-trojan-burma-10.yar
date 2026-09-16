rule Win_Trojan_Burma_10
{
strings:
	$a0 = { 3bbadc01cd21c3b90200b44ebad001cd21b43c33c9ba9e00cd21b74093ba0001b9ba01cd21c3 }


condition:
	$a0
}