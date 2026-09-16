rule Win_Trojan_Bancos_1848
{
strings:
	$a0 = { 21ec2e986f5cb1ff7b02bab7cbacc07b5bf1d0b2d262406d4b23ddc0a7984af8824f49222abc2c28ef557f62716bcfd6c922a4df2eb5f8319f5358e987c343c9999c7fc86759 }


condition:
	$a0
}