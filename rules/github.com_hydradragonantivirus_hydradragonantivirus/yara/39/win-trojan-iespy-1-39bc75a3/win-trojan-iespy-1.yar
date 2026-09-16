rule Win_Trojan_IESpy_1
{
strings:
	$a0 = { 696578706c6f72652e657865 }

	$a1 = { 69656874747073656e64726571756573746d757465785f2575 }

	$a2 = { 504f5354 }


condition:
	$a0 and $a1 and $a2
}