rule Win_Downloader_Banload_1075
{
strings:
	$a0 = { 0bd3085352551e652e865f52cab1b2c30c77cfd1b8fa009afb72a203a6867c1b1f9360f8be9fe5397d7aad7944adb81afabcb0d0f50851 }


condition:
	$a0
}