rule Win_Downloader_130838_1
{
strings:
	$a0 = { 38055ed74a656e6e79ed6819007669746f4141003c8ffacd1c0b35ac0438ab1e35ac3416273c0a4a6868b2 }


condition:
	$a0
}