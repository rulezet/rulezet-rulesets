rule Win_Trojan_FakeCodecs_3
{
strings:
	$a0 = { 558bec6aff6860d340006850c3400064a100000000506489250000000083ec6853565789 }


condition:
	$a0
}