rule Win_Spyware_6778_1
{
strings:
	$a0 = { 565383c40457528bd75ae8e2010000cd }


condition:
	$a0
}