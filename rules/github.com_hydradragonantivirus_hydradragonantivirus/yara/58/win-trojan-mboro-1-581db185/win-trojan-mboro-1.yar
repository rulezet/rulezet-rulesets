rule Win_Trojan_MBoro_1
{
strings:
	$a0 = { cd215ae951ffb80242b90000ba0000cd21b440b91d008d960401cd218db62101b94701518b }


condition:
	$a0
}