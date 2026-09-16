rule Win_Trojan_Stoned_26
{
strings:
	$a0 = { 7cfba113042d0400a31304ba4000f7e22ec706790181002ea37b018ec0be007cbf0000b90001 }


condition:
	$a0
}