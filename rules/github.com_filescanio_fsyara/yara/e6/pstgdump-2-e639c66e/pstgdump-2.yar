rule pstgdump_2 : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "pstgdump"

	strings:
		$s1 = {66 67 64 75 6d 70 5c 70 73 74 67 64 75 6d 70}
		$s2 = {70 73 74 67 64 75 6d 70}
		$s3 = {4f 75 74 6c 6f 6f 6b}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $s* )
}