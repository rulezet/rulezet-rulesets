rule Win_Trojan_Bupt_3
{
strings:
	$a0 = { 890e2700ba800089162a00b80103bb0002cd13720eff061b00b8010333dbb90100cd13ebb2 }


condition:
	$a0
}