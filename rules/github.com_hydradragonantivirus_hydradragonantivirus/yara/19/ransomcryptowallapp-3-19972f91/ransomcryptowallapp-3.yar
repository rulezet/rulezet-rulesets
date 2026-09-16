rule RansomCryptoWallApp_3
{
	meta:
		Description  = "Ransom.CryptoWall.sm"
		ThreatLevel  = "5"

	strings:

		$s0 = "spatopayforwin.com" ascii wide
		$s1 = "bythepaywayall.com" ascii wide
		$s2 = "lowallmoneypool.com" ascii wide
		$s3 = "transoptionpay.com" ascii wide
		$s4 = "HELP_DECRYPT" ascii wide nocase

		$s5 = "speralreaopio.com" ascii wide
        $s6 = "vremlreafpa.com" ascii wide
        $s7 = "wolfwallsreaetpay.com" ascii wide
        $s8 = "askhoreasption.com" ascii wide

	condition:
		any of ($s*)
}