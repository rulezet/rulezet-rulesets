rule Win_Trojan_R_7
{
strings:
	$a0 = { 2c81ed030144448bc505160150eb1eeb300000e81700b9d3018d56003e8b86ef02fec403d0b440cd21e80100 }


condition:
	$a0
}