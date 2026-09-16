rule Win_Trojan_VGEN_41
{
strings:
	$a0 = { 8b7e0c8b058b7e0a8b1d8b7e088b0d8b7e068b15cd108b7e0c89058b7e0a891d8b7e08890d8b7e0689155dca06 }


condition:
	$a0
}