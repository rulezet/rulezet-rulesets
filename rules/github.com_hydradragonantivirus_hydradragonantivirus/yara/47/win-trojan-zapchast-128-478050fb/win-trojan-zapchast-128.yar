rule Win_Trojan_Zapchast_128
{
strings:
	$a0 = { 656d3d6d616c696e67736961 }

	$a1 = { 6e69636b3d676f6c645f676972786c73 }

	$a2 = { 746c653d7733322e696d2e626f742e6d61 }


condition:
	$a0 and $a1 and $a2
}