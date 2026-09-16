rule Win_Trojan_StoneHeart_1
{
strings:
	$a0 = { cd218cc03bc37411fce800005e83c6200e07b90005f3abebef06e80000b42abb4b4ccd2181fb }


condition:
	$a0
}