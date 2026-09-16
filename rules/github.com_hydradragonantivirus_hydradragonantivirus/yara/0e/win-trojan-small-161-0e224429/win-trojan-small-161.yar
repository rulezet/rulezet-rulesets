rule Win_Trojan_Small_161
{
strings:
	$a0 = { 5760fcbeff0003750166a533c98ec1bf0403b1af26803dbf741cf3a48ed966a1840066a3910366a3040066a30c }


condition:
	$a0
}