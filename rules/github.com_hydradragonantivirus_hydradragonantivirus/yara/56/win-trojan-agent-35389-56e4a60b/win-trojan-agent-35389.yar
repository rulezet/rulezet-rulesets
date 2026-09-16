rule Win_Trojan_Agent_35389
{
strings:
	$a0 = { 4b657967656e6e6564206279205a696767790a0a536e44205465616d0a0a }


condition:
	$a0
}