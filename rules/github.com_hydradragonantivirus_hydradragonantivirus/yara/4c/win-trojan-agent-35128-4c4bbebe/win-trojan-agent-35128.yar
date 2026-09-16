rule Win_Trojan_Agent_35128
{
strings:
	$a0 = { 0ee8fbe7f66ed040d64e66de8dc5a9bf5cdab25d956e324350cfb9ce21d13231ffca8e479aaf1d5b1ea8bc63ce9a39ef1e511dac01ea2109186922b40dd1213cf03274577eafb8380a78a550f2bb1d4e }


condition:
	$a0
}