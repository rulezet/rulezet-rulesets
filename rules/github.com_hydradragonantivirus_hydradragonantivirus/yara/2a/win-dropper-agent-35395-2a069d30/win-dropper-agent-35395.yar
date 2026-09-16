rule Win_Dropper_Agent_35395
{
strings:
	$a0 = { 66696e6465722e657865 }

	$a1 = { 696e7374325f3239342e657865 }

	$a2 = { 7363616e2e657865 }

	$a3 = { 6f70656e }


condition:
	$a0 and $a1 and $a2 and $a3
}