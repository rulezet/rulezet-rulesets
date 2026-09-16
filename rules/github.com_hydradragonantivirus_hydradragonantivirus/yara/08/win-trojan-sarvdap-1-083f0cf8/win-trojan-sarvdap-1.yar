rule Win_Trojan_Sarvdap_1
{
strings:
	$a0 = { 7a327348384d556f665145632f47462f4570763146337a32 }


condition:
	$a0
}