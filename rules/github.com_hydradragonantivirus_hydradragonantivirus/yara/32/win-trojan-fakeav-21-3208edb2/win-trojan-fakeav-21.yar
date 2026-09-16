rule Win_Trojan_Fakeav_21
{
strings:
	$a0 = { 89d967e330b9b4bfca0681e90abbca0683c0 }

	$a1 = { 416476616e6365642056697275732052656d6f766572 }


condition:
	$a0 and $a1
}