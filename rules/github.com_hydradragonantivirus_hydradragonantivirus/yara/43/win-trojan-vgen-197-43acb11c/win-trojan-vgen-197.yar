rule Win_Trojan_VGEN_197
{
strings:
	$a0 = { 0400cc8d86a602ffd05113dcfac8bb6ff4ebbf77f5ebbf57f6ebcd1eeb1eeb12ba7fbceb8fcd122416f7305637e8ba }


condition:
	$a0
}