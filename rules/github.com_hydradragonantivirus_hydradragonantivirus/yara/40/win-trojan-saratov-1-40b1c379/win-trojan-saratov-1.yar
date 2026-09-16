rule Win_Trojan_Saratov_1
{
strings:
	$a0 = { c88ed8b89401b9fe072bc8d1e9bb9401befe078a078a2432261c0132061c0188278804434ee2ec }


condition:
	$a0
}