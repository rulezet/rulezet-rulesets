rule Pkep_init__8_byt_64_
{
strings:
	$a0 = { 9405f450817938ab3981058ccde804df6e7cab0763fe4ad747059d2d73a938bab54839100ad8d15a9d6474f88bc53e9abf27559c0c6a7ed8a478964c96bb3ac3 }

condition:
	$a0
}