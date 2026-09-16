rule Win_Trojan_Helicopter_2
{
strings:
	$a0 = { 0351b440b90400ba0803cd215a33c9b80042cd21b440b9080333d2cd211fe85a00b43ecd215f }


condition:
	$a0
}