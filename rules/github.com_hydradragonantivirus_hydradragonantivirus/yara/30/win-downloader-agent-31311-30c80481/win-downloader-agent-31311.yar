rule Win_Downloader_Agent_31311
{
strings:
	$a0 = { 726473782e63630000006469613137310000ba561958e5a0a1a35c1918db3d0baaee3093fc00c955b6221d7e }


condition:
	$a0
}