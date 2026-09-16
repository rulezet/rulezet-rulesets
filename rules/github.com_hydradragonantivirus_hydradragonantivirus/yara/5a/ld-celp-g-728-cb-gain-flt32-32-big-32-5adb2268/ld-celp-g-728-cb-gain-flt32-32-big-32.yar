rule LD_CELP_G_728_cb_gain__flt32___32_big_32_
{
strings:
	$a0 = { 3f0400003f6700003fca20004030dc00bf040000bf670000bfca2000c030dc00 }

condition:
	$a0
}