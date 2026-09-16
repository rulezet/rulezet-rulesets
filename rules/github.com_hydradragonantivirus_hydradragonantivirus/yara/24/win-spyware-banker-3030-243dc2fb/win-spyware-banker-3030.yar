rule Win_Spyware_Banker_3030
{
strings:
	$a0 = { 41f589cbcba1a43ae34a7c113f54257d55f4cb581e935b48a230d97eef18e3840cb168fb7ca46fe92a13c70647 }


condition:
	$a0
}