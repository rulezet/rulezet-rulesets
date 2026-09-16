rule Win_Trojan_Kelly_1
{
strings:
	$a0 = { 5e5683c60eb9f9028034af46e2faf12e41acae1eab7c412364ac5c217168a9f4adafaf258950ac812789afae0e }


condition:
	$a0
}