rule Banker
{
	meta:
		description = "Detects a Banker"
		author = "vitorafonso"
		sample = "e5df30b41b0c50594c2b77c1d5d6916a9ce925f792c563f692426c2d50aa2524"
		report = "https://blog.fortinet.com/2016/11/01/android-banking-malware-masquerades-as-flash-player-targeting-large-banks-and-popular-social-media-apps"

	strings:
		$a1 = "kill_on"
		$a2 = "intercept_down"
		$a3 = "send_sms"
		$a4 = "check_manager_status"
		$a5 = "browserappsupdate"
		$a6 = "YnJvd3NlcmFwcHN1cGRhdGU=" 		$a7 = "browserrestart"
		$a8 = "YnJvd3NlcnJlc3RhcnQ=" 		$a9 = "setMobileDataEnabled"
		$a10 = "adminPhone"

	condition:
		8 of ($a*)

}