rule executable_win_pe {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = /MZ.{76}This program /
condition:
            1 of them
}