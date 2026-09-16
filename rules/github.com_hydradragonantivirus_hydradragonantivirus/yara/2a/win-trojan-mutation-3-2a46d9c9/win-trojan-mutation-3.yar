rule Win_Trojan_Mutation_3
{
strings:
	$a0 = { 5d81ed0301b82435cd21899e7f018c868101b4258d967c01cd210e07b4098d968601cd218d8600008d9e0001b9 }


condition:
	$a0
}