rule Win_Spyware_Goldun_140
{
strings:
	$a0 = { 6f0ae4f1a5008cab66e1c3a4b7d807e3587f33a0a39691c8252b8303607e9766f49ac8769be97c2003bf84fad08e5ea84fbad707573f31816e715ad568cc6ca04ce2cb3df00ee3b4c14045 }


condition:
	$a0
}