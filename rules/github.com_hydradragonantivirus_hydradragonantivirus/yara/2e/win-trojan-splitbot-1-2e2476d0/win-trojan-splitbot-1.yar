rule Win_Trojan_Splitbot_1
{
strings:
	$a0 = { 83c40cc745fc06000000bac81a40008d4ddcff1574104000c745fc07000000ba241b40008d4dd8ff1574104000 }


condition:
	$a0
}