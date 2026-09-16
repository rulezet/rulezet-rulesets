rule Win_Trojan_Philis_109
{
strings:
	$a0 = { 57565f81c78d6fe8118bf75f5456688d6fe8115e2934245e8934 }


condition:
	$a0
}