rule Win_Trojan_Fakebill_2
{
strings:
	$a0 = { 7a0075006c00750073 }

	$a1 = { 25212121212115071212121315212121130c0ba60b3d22fefefefefefefefefe252121212121920ba515130c0b0b0808 }


condition:
	$a0 and $a1
}