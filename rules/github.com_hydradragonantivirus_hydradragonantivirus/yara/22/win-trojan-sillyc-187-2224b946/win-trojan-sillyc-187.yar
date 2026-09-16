rule Win_Trojan_SillyC_187
{
strings:
	$a0 = { 03003e8986e802b2e93e8896e7028d960601b97401b440cd21b8004233d233c9cd21b903008d96 }


condition:
	$a0
}