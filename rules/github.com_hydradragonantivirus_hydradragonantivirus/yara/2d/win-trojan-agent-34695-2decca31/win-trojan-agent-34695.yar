rule Win_Trojan_Agent_34695
{
strings:
	$a0 = { 5283e20053515056570f84d1ffffff6358e30e9888fb0b1111cb9e8f2df2f94fb928026fe925a6f63bbf }


condition:
	$a0
}