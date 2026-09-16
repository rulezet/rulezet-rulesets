rule Win_Trojan_Vengence_1
{
strings:
	$a0 = { b44ecd217222ba9e00b8023dcd2172189353b1c283c262b440cd21720bb43e5bcd21b44fcd2173decd20 }


condition:
	$a0
}