rule Win_Trojan_Ph33r_4
{
strings:
	$a0 = { b8ff51cd213d51ff7416b802faba455932dbcd168cd8488ed833ff803d597701c3816d03a700 }


condition:
	$a0
}