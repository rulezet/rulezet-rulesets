rule Win_Trojan_Bifrose_188
{
strings:
	$a0 = { a4b0e9d98e4afe98a800545aee8a67d2026c00a63bf5582e2aa11800cb12eb38debd5c3fe65a07856afa8b7d6e8049048fd4320082d980f783c1a120007e54be211229f9 }


condition:
	$a0
}