rule RogueUnknownFakeAV
{
	meta:
		Description  = "Rogue.FakeRean.rc"
		ThreatLevel  = "5"
		
	strings:
		$a = "S:\\appointed\\commanding\\general\\Moravia\\Image[01].exe" ascii wide
		$b = "Dresden blockade" ascii wide
		$c = "37592837532" ascii wide
		$d = "39874598234" ascii wide
		$e = "465234750238947532649587203948523-4572304750329458-23459723450-23457" ascii wide
		
	condition:
		($a and $b) or ($c and $d) or $e
}