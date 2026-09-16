rule Win_Trojan_VCode_5
{
strings:
	$a0 = { 22008cc88ed88ec08ed0bcfeffc706ec0952468bfcc60555803d557409bcec09e88b02e93801e88502a14a00a3 }


condition:
	$a0
}