rule apt_hanover_slidewin_pdb
{
	 meta:

		 description = "Rule to detect hanover slidewin samples"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-01-05"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Hanover"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 hash = "89b80267f9c7fc291474e5751c2e42838fdab7a5cbd50a322ed8f8efc3d2ce83"

	 strings:

		 $pdb = "\\Users\\God\\Desktop\\ThreadScheduler-aapnews-Catroot2\\Release\\ThreadScheduler.pdb"
		 $pdb1 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-hostzi\\Release\\slidebar.pdb"
		 $pdb2 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-spectram\\Release\\slidebar.pdb"
		 $pdb3 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-zendossier\\Release\\slidebar.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 100KB and
	 	any of them
}