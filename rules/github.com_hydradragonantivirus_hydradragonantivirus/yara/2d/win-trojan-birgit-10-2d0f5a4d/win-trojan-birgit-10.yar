rule Win_Trojan_Birgit_10
{
strings:
	$a0 = { 5b53e868feb440b9e7038d960a01cd215b53b801573e8b8e98033e8b969a03cd215bb43ecd21 }


condition:
	$a0
}