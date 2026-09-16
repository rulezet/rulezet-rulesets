rule Win_Trojan_Eraser_2
{
strings:
	$a0 = { 5b0e59e833073bc3751d3bc175192e813e0301524575082ec6842b0102eb132ec6842b0103eb0b2ec6842b0104 }


condition:
	$a0
}