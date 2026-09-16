rule Win_Downloader_Swizzor_490
{
strings:
	$a0 = { 0e4bced46ff0f5d9985d34b3ee7e09508d208a145bc004037511232931ab5cc0962587bf6576e60adf64c9223f3bda35ee0b6ed7dfbad8c123d22bdc4339c7964fea6fe63b3aeedc00fbfc10853a }


condition:
	$a0
}