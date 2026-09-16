rule Win_Trojan_MrRat_1
{
strings:
	$a0 = { 128beebf0001fca5a5e81f007403e823000eb80001508cc88ed88ec033c08bd88bc88bd08bf08bf88be8cbb882 }


condition:
	$a0
}