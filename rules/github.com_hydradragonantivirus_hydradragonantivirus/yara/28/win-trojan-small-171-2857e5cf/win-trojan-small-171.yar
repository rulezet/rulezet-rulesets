rule Win_Trojan_Small_171
{
strings:
	$a0 = { 015760fcbeff0003750166a533c98ec1bf0402b1e426803dbf741cf3a48ed966a1840066a3ca0266a3040066a30c }


condition:
	$a0
}