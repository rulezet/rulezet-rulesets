rule Win_Trojan_Koniec_1
{
strings:
	$a0 = { 0450cb742ba39502b8004233c933d2cd21b440b90600ba9302cd2172132bc9b802422bd2cd21 }


condition:
	$a0
}