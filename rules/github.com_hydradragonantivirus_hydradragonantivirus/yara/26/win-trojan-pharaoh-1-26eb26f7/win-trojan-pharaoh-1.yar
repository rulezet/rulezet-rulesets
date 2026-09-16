rule Win_Trojan_Pharaoh_1
{
strings:
	$a0 = { e800005d81ed0301b944038db617018bfeac3404aae2fa }


condition:
	$a0
}