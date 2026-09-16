rule Win_Spyware_Banker_2726
{
strings:
	$a0 = { 99e5eb1ab55b44179c8398680b8d16799973a2630cc4db757e3a35a3b191ab52f0ae58ca7c8b5b58a38f68d430ceeff068fcb179826c51fe17c9 }


condition:
	$a0
}