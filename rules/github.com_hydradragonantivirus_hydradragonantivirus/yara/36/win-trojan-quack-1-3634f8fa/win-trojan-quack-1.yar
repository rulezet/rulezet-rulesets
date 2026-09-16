rule Win_Trojan_Quack_1
{
strings:
	$a0 = { 213c027301c38cdf8b3602002e893ef3012bf781fe00107203be0010bbd43281c3fe07730ee84d0433c050e8c2 }


condition:
	$a0
}