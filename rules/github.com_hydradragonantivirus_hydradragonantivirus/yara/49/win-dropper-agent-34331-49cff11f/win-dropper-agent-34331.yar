rule Win_Dropper_Agent_34331
{
strings:
	$a0 = { a19f9fff969595ffcecdccfffffffffffdfdfdffffffffffffffffff9e9c9cffb3b2b3de17161a30a4a19f94bcbab9ffaca9a7ffa5a3a1ffb0adabff9a9795c64746454128262af62d2b2eff302e31ff908e8bffcac7c6ffc5c3c2ffc3c2c0ff }

	$a1 = { 5d0000800000741c7c18800064c7822d11a4e85688b5f2ab6b12acfd444628a162246e15fa9e3ab54b }


condition:
	$a0 and $a1
}