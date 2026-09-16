rule Win_Spyware_Banker_5458
{
strings:
	$a0 = { 5b6ee9eadd69d8068d4ccb24df9310619d2df89205cb07832d3c0cafedfa2421f54f8b2e6966f3de21d92fee3ec8316f0fc47f6ed00b484dd6ecdcbec4b5d0d762356fd2ab0fa10b13e3d3d5f6c2 }


condition:
	$a0
}