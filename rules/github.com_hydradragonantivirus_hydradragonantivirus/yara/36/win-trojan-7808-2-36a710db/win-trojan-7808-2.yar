rule Win_Trojan_7808_2
{
strings:
	$a0 = { 1200f7e28bf881c75c031e579a7a099b00bfa3020e579a7a099b00a0560030e4ba1200f7e28bf8 }


condition:
	$a0
}