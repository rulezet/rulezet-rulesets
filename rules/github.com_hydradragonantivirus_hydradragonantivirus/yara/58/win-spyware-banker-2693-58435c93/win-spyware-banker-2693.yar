rule Win_Spyware_Banker_2693
{
strings:
	$a0 = { e85cd610da75db6abd4d21002152d86a012a20aa864da522ecfe2f08eadfd887a7734785ade7a1d8d4c1ee6693bbb00559980b93366e08e66ddb5c579cced725e4e53cf7dcee14894de6fc }


condition:
	$a0
}