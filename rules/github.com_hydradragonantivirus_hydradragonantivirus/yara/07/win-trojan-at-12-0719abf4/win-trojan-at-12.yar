rule Win_Trojan_AT_12
{
strings:
	$a0 = { 12b106d3e08ec026803ffa74258ec3bb0002b80102ba8000b90100cd137213b403b10dcd13720b }


condition:
	$a0
}