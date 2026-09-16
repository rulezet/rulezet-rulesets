rule Win_Downloader_Swizzor_554
{
strings:
	$a0 = { c5d894319db06ea27a11985d9d176481d6a9983f8f704a8fe899e60e72440b3ecc853c16d17ab67bd871cc6fd2c5c943527ac60e7ae49e27cf4e6b99cceafa1f68ed33607ea26d46deca4d7c }


condition:
	$a0
}