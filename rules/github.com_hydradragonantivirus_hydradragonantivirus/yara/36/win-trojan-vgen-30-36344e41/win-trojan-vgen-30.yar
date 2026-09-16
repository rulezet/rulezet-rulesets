rule Win_Trojan_Vgen_30
{
strings:
	$a0 = { 061f8cd80510000500008ed0bc00008cd805100005000050b800005033c033db33c933d233f633ffcbfcb8ff51 }


condition:
	$a0
}