rule Win_Trojan_Necros_1
{
strings:
	$a0 = { e53cb9933833cdbef03d33f5312ceb004d464975 }


condition:
	$a0
}