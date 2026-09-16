rule Win_Trojan_Small_160
{
strings:
	$a0 = { 015760fcbeff0003750166a533c98ec1bf0402b1ae26803dbf741cf3a48ed966a1840066a39b0266a3040066a30c }


condition:
	$a0
}