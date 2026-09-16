rule Win_Dropper_Agent_34347
{
strings:
	$a0 = { 5c??????????2e6578652065202d6f2b202d70 }

	$a1 = { 4e756c6c736f667420496e7374 }


condition:
	$a0 and $a1
}