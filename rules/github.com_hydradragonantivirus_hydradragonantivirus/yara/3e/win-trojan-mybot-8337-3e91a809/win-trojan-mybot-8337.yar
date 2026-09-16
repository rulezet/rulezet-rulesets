rule Win_Trojan_Mybot_8337
{
strings:
	$a0 = { 2e2c946184d6d66fc25b15497b6f621ed08aa7d083fb2dd331d9aee21a4c284638a2b4cd3e6e8b240caabbf252ff570d4d44974456b6e32cf0891389723f3ea4b8ebdd1fe9764a8b2017b06f0b04e7aa }


condition:
	$a0
}