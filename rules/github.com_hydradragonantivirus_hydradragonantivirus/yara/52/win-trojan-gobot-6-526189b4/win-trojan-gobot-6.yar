rule Win_Trojan_Gobot_6
{
strings:
	$a0 = { 5affd2b802faba455932dbcd16b82435cd218c063809891e3a09b82425bad902cd211e07fe062d07b44e33c9 }


condition:
	$a0
}