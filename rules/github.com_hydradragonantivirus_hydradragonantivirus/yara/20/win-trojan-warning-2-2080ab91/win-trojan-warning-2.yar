rule Win_Trojan_Warning_2
{
strings:
	$a0 = { 5e83ee065681c68001a5a5b41a5a8bfa81c29202cd218bd781c27a01e8fe00fc8aa58401b9ff }


condition:
	$a0
}