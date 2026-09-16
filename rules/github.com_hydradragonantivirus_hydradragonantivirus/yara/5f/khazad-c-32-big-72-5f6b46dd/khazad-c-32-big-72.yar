rule khazad_c__32_big_72_
{
strings:
	$a0 = { ba542f7453d3d24d50ac8dbf70529a4cead597d133515ba6de48a899db32b7fce39e919be2bb416ea5cb6b95a1f3b102ccc41d14c363da5d5fdc7dcd7f5a6c5cf726ffede89d6f8e }

condition:
	$a0
}