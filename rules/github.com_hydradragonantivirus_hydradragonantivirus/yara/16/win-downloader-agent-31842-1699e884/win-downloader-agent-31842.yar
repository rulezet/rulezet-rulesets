rule Win_Downloader_Agent_31842
{
strings:
	$a0 = { 4b6abdf29c7ac402af83c2f11fb36b86fd2824e80876dd7723dfbc2dcbe48c436ecfd35132c7135d8dc17c9513b9148b6a9f4db02b59cc0a4dc3cbc36c1fb6d14884d29b3659b10e45f598 }


condition:
	$a0
}