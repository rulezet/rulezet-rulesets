rule Win_Trojan_VGEN_516
{
strings:
	$a0 = { cd211f5a59e80600b43ecd215ec3b80143cd21c3595aebeab4429933c9cd218bd0b440b903 }


condition:
	$a0
}