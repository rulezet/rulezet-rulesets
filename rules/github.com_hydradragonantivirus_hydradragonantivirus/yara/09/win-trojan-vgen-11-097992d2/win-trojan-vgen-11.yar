rule Win_Trojan_VGEN_11
{
strings:
	$a0 = { 5d81ed03018cd80500108ec01e8ed833d2b41acd211fba540103d5b53fb44ecd217303e99100ba1e001e061fb8023dcd }


condition:
	$a0
}