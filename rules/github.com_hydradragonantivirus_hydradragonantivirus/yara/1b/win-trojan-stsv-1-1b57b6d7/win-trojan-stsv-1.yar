rule Win_Trojan_Stsv_1
{
strings:
	$a0 = { c706d000b003c606d200cfb82425bad000cd21b419cd2150b40eb202cd218cc880c4108ec0be000133ffb9c800f3a4bad300b41acd21baaf01b106b44ecd21 }


condition:
	$a0
}