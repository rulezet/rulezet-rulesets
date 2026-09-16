rule Win_Spyware_Banker_2703
{
strings:
	$a0 = { 60c6608a9a7ea69c05f9925104c782eeb14effba82c57f322b6d642d12381ddf45441dc14d0decf53aca8436e2f535bbc50c19e0b9262d5477ee6854ae3d7ceb25969b050acf3866da9c63814caa }


condition:
	$a0
}