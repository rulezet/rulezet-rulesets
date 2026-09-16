rule Win_Trojan_Stryx_1
{
strings:
	$a0 = { 0351b83900ba3917cd15b439cd15b90200b439ba3b01cd21eb00bf3b01bb0700fe018039397606c601304b75f359 }


condition:
	$a0
}