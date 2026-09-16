rule MD5MAC__32_lil_48_
{
strings:
	$a0 = { 97ef45ac290f43cd457e1b551c801134b177ce962e728e7c5f5aab0a3643be189d21b421bc87b94da29d27bdc75bd7c3 }

condition:
	$a0
}