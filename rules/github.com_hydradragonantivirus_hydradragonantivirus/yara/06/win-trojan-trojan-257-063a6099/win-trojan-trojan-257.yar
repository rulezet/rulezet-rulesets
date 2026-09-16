rule Win_Trojan_Trojan_257
{
strings:
	$a0 = { e8000058feccb104d3e88ccb03c350b8140150cbfa8cc88ed0bc06110606a102000e1fa3bf0fe84a00a1bf0f071fa30200b00022c07519bb00012ea18c0f89072ea08e }


condition:
	$a0
}