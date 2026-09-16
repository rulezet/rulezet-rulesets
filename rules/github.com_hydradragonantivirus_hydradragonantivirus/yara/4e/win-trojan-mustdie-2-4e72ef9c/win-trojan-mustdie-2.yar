rule Win_Trojan_MustDie_2
{
strings:
	$a0 = { 18c1eb4c5b1ac1eb4c7b24c1eb4c7326c17d6b6b08e4f8a881b0c62c54c5718d7ea7c508e4b7c38d }


condition:
	$a0
}