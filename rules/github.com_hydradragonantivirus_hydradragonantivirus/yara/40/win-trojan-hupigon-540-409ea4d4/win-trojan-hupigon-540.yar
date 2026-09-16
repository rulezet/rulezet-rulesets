rule Win_Trojan_Hupigon_540
{
strings:
	$a0 = { 271e4fe0fa4c8320d4bc569b211a7504b9e903f380553b81e8c0c973b580dd108a64bb88119b270f7b436772bbeff0acfe9fc95ba433bfeef2e7127d688b618b4e45f4b48c5c7f52d41e95f0839a }


condition:
	$a0
}