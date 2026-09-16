rule Win_Trojan_SdBot_3633
{
strings:
	$a0 = { df06d2d7065626f563903a880171c976225dca1cdaa708c052d016af282d9871a0c3ce18a1e319b1f5e4f76ec9d14ebef7cf7bc5c97637ae96da0d339aeec8ee2bd0946e6a525b8847b3d432faae }


condition:
	$a0
}