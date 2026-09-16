rule Win_Trojan_Telefonica_1
{
strings:
	$a0 = { 7c33c08ed08be38ed8fbb106a1130448a31304d3e08ec00e1fb9000133ff8bf3fcf3a5bbe3000653cbbe918b96 }


condition:
	$a0
}