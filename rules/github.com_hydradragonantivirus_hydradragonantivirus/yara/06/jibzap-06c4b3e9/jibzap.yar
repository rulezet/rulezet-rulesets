rule jibzap
{
	meta:
		author = "PEiD"
		description = "APatch GUI 1.x -> Joergen Ibsen"
		group = "126"
		function = "0"
	strings:
		$a0 = { 52 31 C0 E8 FF FF FF FF }
	condition:
		$a0
}