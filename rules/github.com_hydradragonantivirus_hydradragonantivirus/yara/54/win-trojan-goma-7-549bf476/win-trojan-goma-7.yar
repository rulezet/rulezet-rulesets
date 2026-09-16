rule Win_Trojan_Goma_7
{
strings:
	$a0 = { fc08f2a72fe92dafe93488d761efe6eff8aa7143fc1e6befa3cce319fc10afed3964026f2905a4bd }


condition:
	$a0
}