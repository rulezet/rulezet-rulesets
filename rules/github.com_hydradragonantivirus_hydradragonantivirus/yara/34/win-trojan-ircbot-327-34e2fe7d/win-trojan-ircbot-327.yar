rule Win_Trojan_IRCBot_327
{
strings:
	$a0 = { d0c64ed824f8b3406a0642e6edd1aec8f8b3fc013b89e9de0e9c4ccac082cca004cac062cc9ccfe6013a3ecbcceadfedf893cd92dbcfd0ca9c01b6dfba186ae9c8cccc30eadff1b6a16a36cbccffdfed }


condition:
	$a0
}