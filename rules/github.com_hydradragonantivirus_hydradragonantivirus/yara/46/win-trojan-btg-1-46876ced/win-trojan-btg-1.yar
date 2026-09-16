rule Win_Trojan_Btg_1
{
strings:
	$a0 = { 8bcab43fcd215052e8be015a59b440cd215a721b33c9b80042cd21b440cd218bce8bd780f1 }


condition:
	$a0
}