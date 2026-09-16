rule Win_Trojan_AGIP_1
{
strings:
	$a0 = { 7f35cd218cd88ec083fbff7503e99000baffffb87f25cd }


condition:
	$a0
}