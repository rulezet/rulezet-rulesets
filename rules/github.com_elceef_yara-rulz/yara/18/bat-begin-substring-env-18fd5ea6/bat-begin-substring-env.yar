rule BAT_Begin_Substring_Env
{
	meta:
		description = "Detects suspicious substring syntax at the begining of batch script"
		author = "marcin@ulikowski.pl"
		date = "2023-06-02"
		hash1 = "8ace121fae472cc7ce896c91a3f1743d5ccc8a389bc3152578c4782171c69e87"
		reference = "https://cybersecurity.att.com/blogs/labs-research/seroxen-rat-for-sale"

	strings:
		$echo = "@echo off"
		$substr = { 3a 7e ( 3? 2c 3? | 2d 3? 2c 3? | 3? 2c 2d 3? | 3? 3? 2c 3? | 2d 3? 3? 2c 3? | 3? 3? 2c 2d 3? ) 25 }

	condition:
		$echo in (0..4) and
		$substr in (10..100)
}