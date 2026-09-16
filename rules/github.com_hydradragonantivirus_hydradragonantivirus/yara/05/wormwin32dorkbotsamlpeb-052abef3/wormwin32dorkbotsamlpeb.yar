rule WormWin32DorkbotSamlpeB
{
 	meta:
 		Description  = "Worm.Dorkbot.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = "http://ht.ly/jZH8A?yd=" ascii wide
		$ = "DecriptedFiles" ascii wide
		$ = "Infected Drive: %s" ascii wide
		$a = "snkb00pt" ascii wide

 	condition:
 		(3 of them) or $a
}