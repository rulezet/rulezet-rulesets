rule Win_Trojan_Leprosy_22
{
strings:
	$a0 = { 03be37018bfefcad331e0201ab49e302ebf559c3ba00018b1ef801b92a02e8dcffb80040cd21e8d4ffc33c4a3e }


condition:
	$a0
}