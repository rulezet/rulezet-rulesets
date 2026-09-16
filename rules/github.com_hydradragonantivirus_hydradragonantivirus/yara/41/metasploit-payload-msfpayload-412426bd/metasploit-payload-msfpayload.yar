rule metasploit_payload_msfpayload
{
	meta:
		description = "This rule detects generic metasploit callback payloads generated with msfpayload"
		Author = "Adam Burt (adam_burt@symantec.com)"
	strings:
		$a1 = "asf"
		$a2 = "release"
		$a3 = "build"
		$a4 = "support"
		$a5 = "ab.pdb"
		$l1 = "WS2_32.dll"
		$l2 = "mswsock"
		$l3 = "ntdll.dll"
		$l4 = "KERNEL32.dll"
		$l5 = "shell32"
		$l6 = "malloc"
		$l7 = "fopen"
		$l8 = "fclose"
		$l9 = "fprintf"
		$l10 = "strncpy"
	condition:
		all of ($l*)
		and all of ($a*)

}