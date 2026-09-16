rule Win_Trojan_Helloween_1
{
strings:
	$a0 = { 2fc97505b8696aeb069d2eff2e0a009dcfb003cfb43feb02b43ee8150072022bc1c333c933d2 }


condition:
	$a0
}