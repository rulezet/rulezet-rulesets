rule Win_Trojan_Fakeav_27
{
strings:
	$a0 = { 29d252ff923060990085d27403c201008d0cd5060800006800cea3 }

	$a1 = { 30736644246225254e237550 }

	$a2 = { 42255c224e86f638e236 }


condition:
	$a0 and $a1 and $a2
}