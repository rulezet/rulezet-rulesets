import "pe"
rule VM_Detect_Username_Filepath_DriveSize
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Check filepaths and drive size and Sandbox usernames"
	strings:
				$path1 = "SANDBOX" wide ascii
		$path2 = "\\SAMPLE" wide ascii
		$path3 = "\\VIRUS" wide ascii

				$physicaldrive = "\\\\.\\PhysicalDrive0" wide ascii nocase
		$dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15} 
				$user1 = "MALTEST" wide ascii
		$user2 = "TEQUILABOOMBOOM" wide ascii
		$user3 = "SANDBOX" wide ascii
		$user4 = "VIRUS" wide ascii
		$user5 = "MALWARE" wide ascii
	condition:
		all of ($path*) and pe.imports("kernel32.dll","GetModuleFileNameA") or
		pe.imports("kernel32.dll","CreateFileA") and
		pe.imports("kernel32.dll","DeviceIoControl") and
		$dwIoControlCode and $physicaldrive or
		all of ($user*)  and pe.imports("advapi32.dll","GetUserNameA")
}