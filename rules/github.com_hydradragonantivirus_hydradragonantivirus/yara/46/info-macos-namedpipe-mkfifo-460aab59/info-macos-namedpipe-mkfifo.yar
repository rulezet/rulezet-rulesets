rule INFO_MacOS_NamedPipe_mkfifo
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for mkfifo command used to create a MacOS named pipe"

	strings:
		$ = "mkfifo" ascii wide
	condition:
		all of them
}