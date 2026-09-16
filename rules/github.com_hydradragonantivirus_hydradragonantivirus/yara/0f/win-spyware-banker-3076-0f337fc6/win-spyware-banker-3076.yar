rule Win_Spyware_Banker_3076
{
strings:
	$a0 = { ea8062fadc4379fedcf8241543c669bbfb305933778c9aeca8b57db8fdaaf63b707dc487103c3e13a58307ed6ee1f05452ce }


condition:
	$a0
}