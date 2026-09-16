rule Win_Trojan_Uruguay_3
{
strings:
	$a0 = { 43e247f9a2079aad49843a7b0d3e482c07880720d107b3fd51c2bc33fbfbf96e2b5b53fc2d5bf7af2d3dd1bb2d3cf3df }


condition:
	$a0
}