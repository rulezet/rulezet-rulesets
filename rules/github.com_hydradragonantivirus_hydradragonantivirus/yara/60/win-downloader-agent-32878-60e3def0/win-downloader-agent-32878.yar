rule Win_Downloader_Agent_32878
{
strings:
	$a0 = { e6151b909a517026013c28185391ae5efa79c8f6a083e2a751b6f930025de3906edd8f0cc53eb395c46b914cee0a97109e47f72e6493612fcb35ce682dca }


condition:
	$a0
}