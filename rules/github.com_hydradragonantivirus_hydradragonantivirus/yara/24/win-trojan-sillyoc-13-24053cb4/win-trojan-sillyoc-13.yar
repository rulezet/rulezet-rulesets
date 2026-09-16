rule Win_Trojan_SillyOC_13
{
strings:
	$a0 = { 3db001ba9e00cd21720d93b440b9a500ba0001cd217200b801432e8b0e9500ba9e00cd21b80157 }


condition:
	$a0
}