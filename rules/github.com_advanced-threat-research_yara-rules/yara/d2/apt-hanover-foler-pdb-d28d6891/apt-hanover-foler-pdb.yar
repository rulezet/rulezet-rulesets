rule apt_hanover_foler_pdb
{
	 meta:

		 description = "Rule to detect hanover foler samples"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-01-05"
		 rule_version = "v1"
      	 malware_type = "backdoor"
         malware_family = "Backdoor:W32/Hanover"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 hash = "bd77d7f8af8329dfb0bcc0624d6d824d427fbaf859ab2dedd8629aa2f3b7ae0d"

	 strings:

		 $pdb = "\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb"
		 $pdb1 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\Release\\UsbP.pdb"
		 $pdb2 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\UsbP - u\\Release\\UsbP.pdb"
		 $pdb3 = "\\Monthly Task\\August 2011\\USB Prop\\Usb Propagator.09-24\\nn\\Release\\nn.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 480KB and
	 	any of them
}