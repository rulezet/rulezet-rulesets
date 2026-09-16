rule Win_Trojan_Agent_35107
{
strings:
	$a0 = { 53c7606e669cfe985bbe46e1480b958ed244960cd07a375c2cc0c28956c667cccc245cff7a24d8cffa8f582a0e2ebece620aa742c3cddec850430427 }


condition:
	$a0
}