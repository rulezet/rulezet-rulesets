rule Win_Downloader_67633_1
{
strings:
	$a0 = { e809016235e909010ad8558bec81ec2803 }

	$a1 = { 747275653d31266c6f67696e3d }


condition:
	$a0 and $a1
}