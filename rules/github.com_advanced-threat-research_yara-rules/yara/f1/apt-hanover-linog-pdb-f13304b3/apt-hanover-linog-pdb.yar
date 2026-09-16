rule apt_hanover_linog_pdb
{
	 meta:
		 description = "Rule to detect hanover linog samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-01-05"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Hanover"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 hash = "f6319fd0e1d3b9d3694c46f80208e70b389e7dcc6aaad2508b80575c604c5dba"

	 strings:

		 $pdb = "\\Users\\hp\\Desktop\\download\\Release\\download.pdb"
		 $pdb1 = "\\Backup-HP-ABCD-PC\\download\\Release\\download.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 165KB and
	 	any of them
}