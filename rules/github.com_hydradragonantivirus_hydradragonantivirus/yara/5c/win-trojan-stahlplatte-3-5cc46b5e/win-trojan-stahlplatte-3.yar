rule Win_Trojan_Stahlplatte_3
{
strings:
	$a0 = { 90900e58bb007f39d87203e947018ec3be0000bf0008b90001f3a48ec01ee9b1018ed8b447b20031f6cd211f06b8007f8ec0b90400bebc02bf0001f3a507b44e }


condition:
	$a0
}