rule Win_Trojan_Stoned_66
{
strings:
	$a0 = { 0102bb000241b280cd13803eb70337742db8010341cd13bfb801beb803b94800 }


condition:
	$a0
}