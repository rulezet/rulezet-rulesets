rule Win_Trojan_SillyC_79
{
strings:
	$a0 = { 40b903008d94af01cd21b8024233c933d2cd21b440b9bb008bd681c20001cd21b80157b96464ba }


condition:
	$a0
}