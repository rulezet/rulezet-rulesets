rule Win_Trojan_Seat_2
{
strings:
	$a0 = { 52a3148f458eb25aae9bac0ecbe2918d7d01b6473b8f458eb25aae299bf5a48f29 }


condition:
	$a0
}