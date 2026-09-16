rule Win_Trojan_Bancos_907
{
strings:
	$a0 = { 714e075f67ecf3b2d17efec79f8c7a4bffc4ba5c59a9903386e19e138e6755b90135faad191ea6411059cafffcf3e5daac68773ad20e7eaf60094fbb157a71c66d95812da21313d9f61b78614711ce10e654 }


condition:
	$a0
}