rule macos_bundle_findersync_appex
{
	meta:
		description = "Identify macOS Finder Sync plugins - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.04.09"
		reference = "https://theevilbit.github.io/beyond/beyond_0026/"
		DaysofYARA = "99/100"

	strings:
		$interface = "FinderSync"

	condition:
		(
			uint32(0) == 0xfeedface or 			uint32(0) == 0xcefaedfe or 			uint32(0) == 0xfeedfacf or 			uint32(0) == 0xcffaedfe or 			uint32(0) == 0xcafebabe or 			uint32(0) == 0xbebafeca    		) and
		any of them
}