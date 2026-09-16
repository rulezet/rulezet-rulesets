rule Win_Spyware_Agent_31803
{
strings:
	$a0 = { 558bec81ec040100006a016850124000686c124000ff1550104000 }


condition:
	$a0
}