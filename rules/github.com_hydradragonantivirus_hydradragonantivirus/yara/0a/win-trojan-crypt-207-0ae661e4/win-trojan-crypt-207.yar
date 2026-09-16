rule Win_Trojan_Crypt_207
{
strings:
	$a0 = { 60f7d781fb65be002b33d0683410400089cb0fb3f2f7d2c389f7f5bbc3e31511dcd0900fb3f7c1ea0d33ca33 }


condition:
	$a0
}