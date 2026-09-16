rule Win_Trojan_DSME_2
{
strings:
	$a0 = { 48c7b87de3b85f239df1b364c280ff54c2a86336fbb369b39bb2c9f3db5f53af }


condition:
	$a0
}