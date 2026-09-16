rule Win_Trojan_Legion_1
{
strings:
	$a0 = { 7d5c289098ab59ef77a12c984e41d163460b5eeeedd74fe1ab71af004e2cc7df5d0f1657d3bd0b7172e14c702cdf0d37fd30d87864a9da44accab02c91bc }


condition:
	$a0
}