rule Win_Spyware_Sinowal_27
{
strings:
	$a0 = { 8b4dfc3bcb89048d0c68420088187510ff75f868d0664200ff350c684200eb5c }


condition:
	$a0
}