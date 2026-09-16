rule Win_Spyware_Banker_3312
{
strings:
	$a0 = { f06c34b2bb3138e9309731c803caf7aff2e6f5156466c5a10081f470468e8e7eddff38c04e03beb6d391c9c61bbaf90dd5bbfe10a9b1c9de0dd4d86439768717d515206bc8fa }


condition:
	$a0
}