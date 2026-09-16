rule Win_Trojan_Chukcha_1
{
strings:
	$a0 = { 8b1e84018b0e80018d162a03cd21b43e8b1e8401cd21 }


condition:
	$a0
}