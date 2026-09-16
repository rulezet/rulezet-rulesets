import "pe"
rule _Windows_9x_User_password_file_
{
	meta:
		description = "Windows 9x User password file"
	strings:
		$0 = {E3 82 85 96}
	condition:
		$0 at pe.entry_point
}