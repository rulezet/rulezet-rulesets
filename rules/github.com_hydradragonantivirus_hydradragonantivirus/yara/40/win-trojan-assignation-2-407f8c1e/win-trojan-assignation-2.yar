rule Win_Trojan_Assignation_2
{
strings:
	$a0 = { 168916010081c2a20483e2fe406789460e67895610b440b98d0233d2e85fffe83600b90002 }


condition:
	$a0
}