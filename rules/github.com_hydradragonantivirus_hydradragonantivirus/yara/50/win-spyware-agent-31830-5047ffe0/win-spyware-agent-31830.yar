rule Win_Spyware_Agent_31830
{
strings:
	$a0 = { 56578d450868f0124000508d45e850e849170000 }


condition:
	$a0
}