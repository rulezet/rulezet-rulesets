rule Win_Trojan_SillyC_48
{
strings:
	$a0 = { 0300894401b440b19b8d56efcd215a3bc17512b800428846798bcacd21b440b104b601cd21b43e }


condition:
	$a0
}