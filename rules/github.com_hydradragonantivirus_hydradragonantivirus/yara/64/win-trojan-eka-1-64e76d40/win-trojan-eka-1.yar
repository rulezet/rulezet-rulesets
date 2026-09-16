rule Win_Trojan_Eka_1
{
strings:
	$a0 = { 1000ba6309b91800c6065d0900b440cd21c3b80042998bcaebf5fb83c408b454cd21b8ffff }


condition:
	$a0
}