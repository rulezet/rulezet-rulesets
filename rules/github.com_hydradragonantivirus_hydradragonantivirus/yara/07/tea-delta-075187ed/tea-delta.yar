rule TEA_DELTA {
	meta:
		author = "_pusher_"
		description = "TEA DELTA"
		date = "2016-02"
	strings:
		$c0 = { B9 79 37 9E }
		$c1 = { 47 86 C8 61 }
	condition:
		any of them
}