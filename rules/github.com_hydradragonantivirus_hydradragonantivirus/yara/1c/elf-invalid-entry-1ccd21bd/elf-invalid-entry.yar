import "elf"
rule elf_invalid_entry
{
	meta:
		description = "Identify ELF file who's pe.entry_point is within the header."
		author = "@shellcromancer"
		version = "0.1"
		date = "2023.01.02"
		reference = "https://n0.lol/ebm/1.html"
		reference = "https://tmpout.sh/1/1.html"
		hash = "05379bbf3f46e05d385bbd853d33a13e7e5d7d50"
		DaysofYARA = "2/100"
	condition:
		(
			uint32(0) == 0x464c457f and
			not defined elf.entry_point
		)
}