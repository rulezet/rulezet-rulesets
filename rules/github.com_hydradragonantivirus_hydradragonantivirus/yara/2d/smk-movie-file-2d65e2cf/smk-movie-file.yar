import "pe"
rule _SMK_movie_file_
{
	meta:
		description = "SMK movie file"
	strings:
		$0 = {53 4D 4B 32}
	condition:
		$0 at pe.entry_point
}