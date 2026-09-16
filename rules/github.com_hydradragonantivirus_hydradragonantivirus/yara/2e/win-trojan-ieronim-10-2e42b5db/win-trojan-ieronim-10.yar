rule Win_Trojan_Ieronim_10
{
strings:
	$a0 = { 0eb8000150cb80fc4b75601e061653561e5250518bd8 }


condition:
	$a0
}