rule Win_Trojan_Badbrain_2
{
strings:
	$a0 = { cd21b419cd218ad0fec2b447be4c02cd21baeb01b43bcd21b91300bae301b44ecd213d120075 }


condition:
	$a0
}