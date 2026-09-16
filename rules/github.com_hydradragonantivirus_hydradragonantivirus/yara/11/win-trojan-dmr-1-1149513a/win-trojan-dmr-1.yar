rule Win_Trojan_DMR_1
{
strings:
	$a0 = { 8bca8bfb83c73090880d4381fbb00475db57e9bbff9c706cebfa256db93b512366010300e9517b9c70d1ab5c2452b98d52080b09574ee5659c }


condition:
	$a0
}