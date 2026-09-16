rule win_stealc_w0 : hardened
{
	meta:
		malware = "Stealc"
		description = "Find standalone Stealc sample based on decryption routine or characteristic strings"
		source = "SEKOIA.IO"
		reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"
		classification = "TLP:CLEAR"
		hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
		author = "crep1x"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealc"
		malpedia_version = "20230221"
		malpedia_license = "CC BY-NC-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		malpedia_rule_date = "20230221"
		malpedia_hash = ""

	strings:
		$dec = { 55 8b ec 8b 4d ?? 83 ec 0c 56 57 e8 ?? ?? ?? ?? 6a 03 33 d2 8b f8 59 f7 f1 8b c7 85 d2 74 04 }
		$str01 = {2d 2d 2d 2d 2d 2d}
		$str02 = {4e 65 74 77 6f 72 6b 20 49 6e 66 6f 3a}
		$str03 = {2d 20 49 50 3a 20 49 50 3f}
		$str04 = {2d 20 43 6f 75 6e 74 72 79 3a 20 49 53 4f 3f}
		$str05 = {2d 20 44 69 73 70 6c 61 79 20 52 65 73 6f 6c 75 74 69 6f 6e 3a}
		$str06 = {55 73 65 72 20 41 67 65 6e 74 73 3a}
		$str07 = {25 73 5c 25 73 5c 25 73}

	condition:
		uint16( 0 ) == 0x5A4D and ( $dec or 5 of ( $str* ) )
}