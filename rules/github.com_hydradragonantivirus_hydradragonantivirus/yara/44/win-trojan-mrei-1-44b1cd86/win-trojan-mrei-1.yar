rule Win_Trojan_MREI_1
{
strings:
	$a0 = { 53515256571e06e800005b83eb0bb8cccccd213dbbbb7450fc8cc0488ec026803e00005a7403eb409026832e030040 }


condition:
	$a0
}