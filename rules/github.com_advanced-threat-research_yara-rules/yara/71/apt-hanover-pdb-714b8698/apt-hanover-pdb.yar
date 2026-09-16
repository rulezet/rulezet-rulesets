rule apt_hanover_pdb
{
	 meta:

		 description = "Rule to detect hanover samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-01-05"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Hanover"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 hash = "a2460412575cdc187dfb69eb2847c5b43156af7f7d94b71422e7f771e8adb51e"
		 

 	strings:

		$pdb = "\\andrew\\Key\\Release\\Keylogger_32.pdb"
		$pdb1 = "\\BACK_UP_RELEASE_28_1_13\\General\\KG\\Release\\winsvcr.pdb"
		$pdb2 = "\\BackUP-Important\\PacketCapAndUpload_Backup\\voipsvcr\\Release\\voipsvcr.pdb"
		$pdb3 = "\\BNaga\\kaam\\New_FTP_2\\Release\\ftpback.pdb"
		$pdb4 = "\\DD0\\DD\\u\\Release\\dataup.pdb"
		$pdb5 = "\\Documents and Settings\\Admin\\Desktop\\Newuploader\\Release\\Newuploader.pdb"
		$pdb6 = "\\Documents and Settings\\Admin\\Desktop\\Uploader Code\\Release\\Newuploader.pdb"
		$pdb7 = "\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb"
		$pdb8 = "\\smse\\Debug\\smse.pdb"
		$pdb9 = "\\Users\\admin\\Documents\\Visual Studio 2008\\Projects\\DNLDR-no-ip\\Release\\DNLDR.pdb"
		$pdb10 = "\\final exe\\check\\Release\\check.pdb"
		$pdb11 = "\\Projects\\Elance\\AppInSecurityGroup\\FtpBackup\\Release\\Backup.pdb"
		$pdb12 = "\\projects\\windows\\MailPasswordDecryptor\\Release\\MailPasswordDecryptor.pdb"
		$pdb13 = "\\final project backup\\UPLODER FTP BASED\\New folder\\Tron 1.2.1(Ftp n Startup)\\Release\\Http_t.pdb"

 	condition:

 	uint16(0) == 0x5a4d and
 	filesize < 1000KB and
 	any of them
}