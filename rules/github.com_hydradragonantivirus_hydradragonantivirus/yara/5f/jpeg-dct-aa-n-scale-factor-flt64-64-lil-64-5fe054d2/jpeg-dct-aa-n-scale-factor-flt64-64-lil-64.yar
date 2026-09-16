rule Jpeg_dct_AA_N_scale_factor__flt64___64_lil_64_
{
strings:
	$a0 = { 000000000000f03fef6148b15031f63fca6f4d91aee7f43faa116cef62d0f23f000000000000f03f3bbfa7c06924e93fbb20c77b7a51e13f5dab72de55a8d13f }

condition:
	$a0
}