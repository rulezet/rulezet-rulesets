rule Win_Trojan_Bancos_776
{
strings:
	$a0 = { d7e948cd4519ebc181055002c31f6bd0f0870b832083d0a57c4c954977cd9ee5cfea0667c9337a4ffa11c72bd8befee5a1bcfa1c2485c0014afbc2a58f424b7c03b1a685 }


condition:
	$a0
}