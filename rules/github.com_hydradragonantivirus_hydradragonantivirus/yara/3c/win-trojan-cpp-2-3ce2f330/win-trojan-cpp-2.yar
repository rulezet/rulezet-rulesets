rule Win_Trojan_CPP_2
{
strings:
	$a0 = { 015760beff00037501fc66a533c98ec1bf0402b1ef26803dbf741cf3a48ed966a1840066a3d50266a3040066a30c }


condition:
	$a0
}