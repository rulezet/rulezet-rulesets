rule Win_Trojan_DirTree_1
{
strings:
	$a0 = { 51b439ba2d01cd21eb0190bf2d01bb0700fe018039397606c601304b75f35983f900740449 }


condition:
	$a0
}