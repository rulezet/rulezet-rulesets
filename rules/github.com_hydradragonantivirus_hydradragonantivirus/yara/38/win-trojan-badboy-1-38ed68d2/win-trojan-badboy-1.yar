rule Win_Trojan_BadBoy_1
{
strings:
	$a0 = { c30253518b078b4f108bd8301f43e2fb }


condition:
	$a0
}