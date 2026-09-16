rule Win_Adware_Lop_193
{
strings:
	$a0 = { f35ce0cf6ecb45fa5d637d602de914c0afe1e454dd6f7145a21eb5c999bd20af1406b3071da062229f9229bb07d820446d17d468670c855b138d32be }


condition:
	$a0
}