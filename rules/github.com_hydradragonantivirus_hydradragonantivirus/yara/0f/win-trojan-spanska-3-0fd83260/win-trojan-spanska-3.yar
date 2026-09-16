rule Win_Trojan_Spanska_3
{
strings:
	$a0 = { 1300cd10bac80332c0ee4233c98ac1ee32c0eeee4183f93f75f333c9b03fee8ac1ee32c0ee4183f93f75f133c9b03f }


condition:
	$a0
}