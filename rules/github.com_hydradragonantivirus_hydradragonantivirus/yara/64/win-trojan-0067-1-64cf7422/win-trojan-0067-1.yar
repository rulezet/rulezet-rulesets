rule Win_Trojan_0067__1
{
strings:
	$a0 = { 07245b53b440b9c4038d960301cd21b003cfb43d8d964105cd2193c3b801438d964105cd21c3 }


condition:
	$a0
}