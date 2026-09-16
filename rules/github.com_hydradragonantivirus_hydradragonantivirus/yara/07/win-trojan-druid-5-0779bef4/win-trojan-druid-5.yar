rule Win_Trojan_Druid_5
{
strings:
	$a0 = { 02ebfcbae401b80125cd21b003cd21bae401b80125cd21b001cd21b44732d2beef01cd21bae501b44ecd217303eb }


condition:
	$a0
}