rule Win_Trojan_Mybot_5479
{
strings:
	$a0 = { eb460af783add0ba73838844f54b0984a22b1da3ccc88b3bb6fbd2af57c6259d5eaf90f3ffcc6341d2e20f51f7750eeb5066683cc9a8e3dd0db87efdd191e630aabe68edec0d }


condition:
	$a0
}