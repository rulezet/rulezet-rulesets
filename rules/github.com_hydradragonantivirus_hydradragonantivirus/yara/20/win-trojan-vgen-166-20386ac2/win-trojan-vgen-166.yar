rule Win_Trojan_VGEN_166
{
strings:
	$a0 = { 22ddcd213d333d75058d567d90ffe2b82135cd21899e92028c869402b80935cd21899ea4058c86a605b81c35cd21 }


condition:
	$a0
}