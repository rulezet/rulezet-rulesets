rule Win_Spyware_54877_1
{
strings:
	$a0 = { 5e435c56c745d01e504a55c745d4353230358bff908bff90908bff9090908bff }


condition:
	$a0
}