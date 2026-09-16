rule BAT_Chunked_Payload_SetEnv
{
	meta:
		description = "Detects batch script storing chunks of payload in random environment variables"
		author = "marcin@ulikowski.pl"
		date = "2023-05-05"
		hash1 = "f73521adbf89be99c4d7ea74ebf7fed815af49ce4dc060656d7c9c631e4d0538"

	strings:
		$echo = "@echo off"
		$set = { ( 0d 0a | 26 20 ) 73 65 74 20 22 [10] 3d [2-6] 22 }

	condition:
		$echo in (0..4) and
		#set > 10
}