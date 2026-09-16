rule Win_Trojan_Subsys_8
{
strings:
	$a0 = { 39e293a4f1edfd284570f397dec86e6686459e5b9c773433d402186bbaacbccf1ca6024262ac607073fb242fb2fad9c2 }


condition:
	$a0
}